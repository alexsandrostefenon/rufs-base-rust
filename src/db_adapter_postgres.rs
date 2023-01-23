use std::{io::Error, sync::{Arc}};

use openapiv3::OpenAPI;
use serde_json::{Value, Number, json};
use tokio_postgres::{NoTls, Client, Row, types::Type};

use crate::entity_manager::EntityManager;

#[derive(Clone,Default)]
pub struct DbAdapterPostgres {
    //pub openapi    : Option<&OpenAPI>,
    client: Option<Arc<Client>>,
    //client: Option<Arc<RwLock<Client>>>,
    tmp: Value,
}

impl DbAdapterPostgres {
    fn get_json(&self, row: &Row) -> Value {
        let mut obj = json!({});

        for idx in 0..row.len() {
            let column = &row.columns()[idx];
            let name = column.name();
            let typ = column.type_();

            let value : Value = match *typ {
                Type::VARCHAR => Value::String(row.get(idx)),
                Type::INT4 => Value::Number(Number::from(row.get::<usize, i32>(idx))),
                Type::INT8 => Value::Number(Number::from(row.get::<usize, i64>(idx))),
                Type::JSONB => row.get(idx),
                Type::JSONB_ARRAY => {
                    let list = row.get::<_, Vec<Value>>(idx);
                    Value::Array(list)
                },
                _ => row.get(idx)
            };

            obj[name] = value;
        }

        obj
    }

    fn get_json_list(&self, rows: &Vec<Row>) -> Vec<Value> {
        let mut list = vec![];

        for row in rows {
            list.push(self.get_json(row));
        }

        list
    }

    pub async fn connect(&mut self, uri :&str) -> Result<(), Error> {
        println!("[DbAdapterPostgres] connect({})", uri);
        let (client, connection) = tokio_postgres::connect(uri, NoTls).await.unwrap();

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {}", e);
            }
        });

        //let client = RwLock::new(client);
        let client = Arc::new(client);
        self.client = Some(client);
        Ok(())
    }
/*
type DbConfig struct {
	driverName             string
	host                   string
	port                   int
	database               string
	user                   string
	password               string
	connectionString       string
	limitQuery             int
	limitQueryExceptions   []string
	requestBodyContentType string
}

type DbClientSql struct {
	dbConfig                   *DbConfig
	missingPrimaryKeys         map[string][]string
	missingForeignKeys         map[string]map[string]string
	aliasMap                   map[string]string
	aliasMapExternalToInternal map[string]any
	openapi                    *OpenApi
	client                     *sql.DB
	sqlTypes                   []string
	rufsTypes                  []string
}

func (dbSql *DbClientSql) Connect() (err error) {
	if dbSql.dbConfig.limitQuery == 0 {
		dbSql.dbConfig.limitQuery = 1000
	}

	dataSourceName := fmt.Sprintf("postgres://%s:%s@localhost:5432/%s", dbSql.dbConfig.user, dbSql.dbConfig.password, dbSql.dbConfig.database)
	dbSql.dbConfig.driverName = "pgx"
	dbSql.client, err = sql.Open(dbSql.dbConfig.driverName, dataSourceName)

	if err != nil {
		return err
	}

	return nil
}

func (dbSql *DbClientSql) Disconnect() error {
	return dbSql.client.Close()
}

func (dbSql *DbClientSql) buildQuery(queryParams map[string]any, params *[]any, orderBy []string) string {
	buildConditions := func(queryParams map[string]any, params *[]any, operator string, conditions *[]string) {
		count := 1

		for fieldName, field := range queryParams {
			/*
				if value, ok := dbSql.options.aliasMapExternalToInternal[fieldName]; ok {
					fieldName = value
				}
			*/
			paramId := fmt.Sprintf("$%d", count)
			count++
			var condition string

			switch value := field.(type) {
			case []any:
				condition = CamelToUnderscore(fieldName) + operator + " ANY (" + paramId + ")"
			case []string:
				fmt.Printf("Unexpected case condition of %s", value)
				condition = CamelToUnderscore(fieldName) + operator + paramId
			default:
				condition = CamelToUnderscore(fieldName) + operator + paramId
			}

			*conditions = append(*conditions, condition)
			*params = append(*params, field)
		}
	}

	conditions := []string{}
	filter, okFilter := queryParams["filter"]
	filterRangeMin, okFilterRangeMin := queryParams["filterRangeMin"]
	filterRangeMax, okFilterRangeMax := queryParams["filterRangeMax"]

	if okFilter || okFilterRangeMin || okFilterRangeMax {
		if okFilter {
			buildConditions(filter.(map[string]any), params, "=", &conditions)
		}
		if okFilterRangeMin {
			buildConditions(filterRangeMin.(map[string]any), params, ">", &conditions)
		}
		if okFilterRangeMax {
			buildConditions(filterRangeMax.(map[string]any), params, "<", &conditions)
		}
	} else if len(queryParams) > 0 {
		buildConditions(queryParams, params, "=", &conditions)
	}

	str := ""

	if len(conditions) > 0 {
		str = " WHERE " + strings.Join(conditions, " AND ")
	}

	if len(orderBy) > 0 {
		orderByInternal := []string{}

		for _, fieldName := range orderBy {
			pos := strings.Index(fieldName, " ")
			extra := ""

			if pos >= 0 {
				extra = fieldName[pos:]
				fieldName = fieldName[0:pos]
			}

			orderByInternal = append(orderByInternal, CamelToUnderscore(fieldName)+extra)
		}

		str = str + " ORDER BY " + strings.Join(orderByInternal, ",")
	}

	return str
}

func (dbSql *DbClientSql) Insert(schemaName string, obj map[string]any) (map[string]any, error) {
	buildInsertSql := func(schemaName string, schema *Schema, obj map[string]any, params *[]any) string {
		tableName := CamelToUnderscore(schemaName)
		strFields := []string{}
		strValues := []string{}
		idx := 1

		for fieldName, value := range obj {
			if property, ok := schema.Properties[fieldName]; ok && property.IdentityGeneration != "" && value == nil {
				continue
			}
			//			if (dbSql.options.aliasMapExternalToInternal[fieldName] != null) fieldName = dbSql.options.aliasMapExternalToInternal[fieldName];
			strFields = append(strFields, CamelToUnderscore(fieldName))
			strValues = append(strValues, fmt.Sprintf("$%d", idx))
			idx++

			switch v := value.(type) {
			case map[string]any:
				b, _ := json.Marshal(v)
				*params = append(*params, string(b))
			case []any:
				elements := []pgtype.JSONB{}

				for _, item := range v {
					b, _ := json.Marshal(item)
					element := pgtype.JSONB{Bytes: b, Status: pgtype.Present}
					elements = append(elements, element)
				}

				dimensions := []pgtype.ArrayDimension{{Length: int32(len(elements)), LowerBound: 1}}
				list := pgtype.JSONBArray{Elements: elements, Dimensions: dimensions, Status: pgtype.Present}
				*params = append(*params, list)
			default:
				*params = append(*params, dbSql.openapi.getValueFromSchema(schema, fieldName, obj))
			}
		}

		return fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s) RETURNING *;`, tableName, strings.Join(strFields, ","), strings.Join(strValues, ","))
	}

	schema, ok := dbSql.openapi.getSchemaFromSchemas(schemaName)

	if !ok {
		return nil, fmt.Errorf(`[dbClientSql.Insert] : Missing schema %s`, schemaName)
	}

	params := []any{}
	sql := buildInsertSql(schemaName, schema, obj, &params)
	fmt.Println(sql)
	rows, err := dbSql.client.Query(sql, params...)

	if err != nil {
		return nil, err
	}

	if rows.Next() == false {
		return nil, fmt.Errorf(`Failt to insert : %s : %s`, sql, rows.Err())
	}

	item, err := dbSql.getMapFromRow(rows, schema)

	if err != nil {
		return nil, err
	}

	return item, nil
}

func (dbSql *DbClientSql) Find(schemaName string, queryParams map[string]any, orderBy []string) ([]map[string]any, error) {
	tableName := CamelToUnderscore(schemaName)
	params := []any{}
	sqlQuery := dbSql.buildQuery(queryParams, &params, orderBy)
	fieldsOut := "*"

	if dbSql.openapi == nil {
		return nil, fmt.Errorf(`Missing openapi`)
	}

	schema, ok := dbSql.openapi.getSchemaFromSchemas(schemaName)

	if !ok {
		return nil, fmt.Errorf(`[dbClientSql.Find] : Missing schema %s`, schemaName)
	}

	count := 0
	names := []string{}

	for fieldName, property := range schema.Properties {
		if property.InternalName != "" {
			count++
			names = append(names, CamelToUnderscore(property.InternalName)+" as "+CamelToUnderscore(fieldName))
		} else {
			names = append(names, CamelToUnderscore(fieldName))
		}
	}

	if count > 0 {
		fieldsOut = strings.Join(names, ",")
	}

	sqlFirst := ""
	sqlLimit := ""

	if slices.Contains(dbSql.dbConfig.limitQueryExceptions, tableName) == false {
		if dbSql.dbConfig.driverName == "firebird" {
			sqlFirst = fmt.Sprintf(`FIRST %d`, dbSql.dbConfig.limitQuery)
		} else {
			sqlLimit = fmt.Sprintf(`LIMIT %d`, dbSql.dbConfig.limitQuery)
		}
	}

	sql := fmt.Sprintf(`SELECT %s %s FROM %s %s %s`, sqlFirst, fieldsOut, tableName, sqlQuery, sqlLimit)
	fmt.Println(sql)
	return dbSql.getArrayMap(sql, params, schema)
}

func (dbSql *DbClientSql) FindOne(tableName string, queryParams map[string]any) (map[string]any, error) {
	list, err := dbSql.Find(tableName, queryParams, []string{})

	if err != nil {
		return nil, err
	}

	if len(list) == 0 {
		return nil, nil
	}

	return list[0], nil
}

func (dbSql *DbClientSql) Update(schemaName string, key map[string]any, obj map[string]any) (map[string]any, error) {
	schema, ok := dbSql.openapi.getSchemaFromSchemas(schemaName)

	if !ok {
		return nil, fmt.Errorf(`[dbClientSql.Insert] : Missing schema %s`, schemaName)
	}

	tableName := CamelToUnderscore(schemaName)
	params := []any{}
	sqlQuery := dbSql.buildQuery(key, &params, []string{})
	list := []string{}
	idx := 1

	for fieldName, value := range obj {
		if property, ok := schema.Properties[fieldName]; ok && property.IdentityGeneration != "" && value == nil {
			continue
		}

		strField := CamelToUnderscore(fieldName)
		strValue := fmt.Sprintf("$%d", idx)
		list = append(list, fmt.Sprintf("%s=%s", strField, strValue))
		idx++

		switch v := value.(type) {
		case map[string]any:
			b, _ := json.Marshal(v)
			params = append(params, string(b))
		case []any:
			elements := []pgtype.JSONB{}

			for _, item := range v {
				b, _ := json.Marshal(item)
				element := pgtype.JSONB{Bytes: b, Status: pgtype.Present}
				elements = append(elements, element)
			}

			dimensions := []pgtype.ArrayDimension{{Length: int32(len(elements)), LowerBound: 1}}
			list := pgtype.JSONBArray{Elements: elements, Dimensions: dimensions, Status: pgtype.Present}
			params = append(params, list)
		default:
			params = append(params, dbSql.openapi.getValueFromSchema(schema, fieldName, obj))
		}
	}

	sql := fmt.Sprintf(`UPDATE %s SET %s %s RETURNING *`, tableName, strings.Join(list, ","), sqlQuery)
	fmt.Println(sql)
	rows, err := dbSql.client.Query(sql, params...)

	if err != nil {
		return nil, err
	}

	if rows.Next() == false {
		return nil, fmt.Errorf(`Failt to update : %s : %s`, sql, rows.Err())
	}

	item, err := dbSql.getMapFromRow(rows, schema)

	if err != nil {
		return nil, err
	}

	return item, nil
}

func (dbSql *DbClientSql) DeleteOne(schemaName string, key map[string]any) error {
	tableName := CamelToUnderscore(schemaName)
	params := []any{}
	sqlQuery := dbSql.buildQuery(key, &params, []string{})
	sql := fmt.Sprintf(`DELETE FROM %s %s`, tableName, sqlQuery)
	fmt.Println(sql)
	result, err := dbSql.client.Exec(sql, params...)

	if err != nil {
		return err
	}

	if numRows, err := result.RowsAffected(); err != nil || numRows != 1 {
		return fmt.Errorf(`[dbClientSql.DeleteOne] : wrong delete numRows = %d, err = %s`, numRows, err)
	}

	return err
}

func (dbSql *DbClientSql) getMapFromRow(rows *sql.Rows, schema *Schema) (map[string]any, error) {
	cols, _ := rows.Columns()
	columns := make([]any, len(cols))
	columnPointers := make([]any, len(cols))

	for i := range columns {
		columnPointers[i] = &columns[i]
	}

	if err := rows.Scan(columnPointers...); err != nil {
		return nil, err
	}

	m := make(map[string]any)

	for i, colName := range cols {
		val := columnPointers[i].(*any)
		fieldName := UnderscoreToCamel(colName, false)

		if schema != nil {
			if field, ok := schema.Properties[fieldName]; ok {
				if field.Type == "object" {
					data := (*val).([]byte)
					obj := map[string]any{}

					if err := json.Unmarshal(data, &obj); err != nil {
						UtilsShowJsonUnmarshalError(string(data), err)
						return nil, err
					}

					m[fieldName] = obj
				} else if field.Type == "array" {
					// {"{\"mask\": 1, \"path\": \"/rufs_group_owner\"}","{\"mask\": 1, \"path\": \"/rufs_group\"}"}
					str1 := (*val).(string)
					//fmt.Printf("\nstr1 :\n%s\n", str1)
					str2 := regexp.MustCompile(`^{"(.*)"}$`).ReplaceAllString(str1, `[${1}]`)
					//fmt.Printf("\nstr2 :\n%s\n", str2)
					str3 := regexp.MustCompile(`\\"`).ReplaceAllString(str2, `"`)
					//fmt.Printf("\nstr3 :\n%s\n", str3)
					str4 := regexp.MustCompile(`}","{`).ReplaceAllString(str3, `},{`)
					//fmt.Printf("\nstr4 :\n%s\n", str4)
					data := []byte(str4)
					obj := []any{}

					if err := json.Unmarshal(data, &obj); err != nil {
						UtilsShowJsonUnmarshalError(string(data), err)
						return nil, err
					}

					m[fieldName] = obj
				}
			}
		}

		if _, ok := m[fieldName]; !ok {
			m[fieldName] = *val
		}
	}

	return m, nil
}

func (dbSql *DbClientSql) getArrayMap(sql string, params []any, schema *Schema) ([]map[string]any, error) {
	rows, err := dbSql.client.Query(sql, params...)

	if err != nil {
		return nil, err
	}

	result := []map[string]any{}

	for rows.Next() {
		item, err := dbSql.getMapFromRow(rows, schema)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}

	return result, nil
}

func (dbSql *DbClientSql) UpdateOpenApi(openapi *OpenApi, options FillOpenApiOptions) error {
	getFieldName := func(columnName string, field *Schema) (fieldName string) {
		fieldName = UnderscoreToCamel(strings.ToLower(columnName), false)
		fieldNameLowerCase := strings.ToLower(fieldName)

		for aliasMapName, value := range dbSql.aliasMap {
			if strings.ToLower(aliasMapName) == fieldNameLowerCase {
				if field != nil {
					field.InternalName = fieldName

					if len(value) > 0 {
						dbSql.aliasMapExternalToInternal[value] = fieldName
					}
				}

				if len(value) > 0 {
					fieldName = value
				} else {
					fieldName = aliasMapName
				}

				break
			}
		}

		return fieldName
	}

	setRef := func(schema *Schema, fieldName string, tableRef string) {
		field := schema.Properties[fieldName]

		if field != nil {
			field.Ref = "#/components/schemas/" + tableRef
		} else {
			log.Printf(`${dbSql.constructor.name}.getTablesInfo.processConstraints.setRef : field ${fieldName} not exists in schema ${schema.name}`)
		}
	}

	processConstraints := func(schemas map[string]*Schema) error {
		sqlInfoConstraints :=
			"SELECT table_name,constraint_name,constraint_type FROM information_schema.table_constraints ORDER BY table_name,constraint_name"
		sqlInfoConstraintsFields :=
			"SELECT constraint_name,column_name,ordinal_position FROM information_schema.key_column_usage ORDER BY constraint_name,ordinal_position"
		sqlInfoConstraintsFieldsRef :=
			"SELECT constraint_name,table_name,column_name FROM information_schema.constraint_column_usage"
		result, err := dbSql.getArrayMap(sqlInfoConstraints, []any{}, nil)

		if err != nil {
			return err
		}

		resultFields, err := dbSql.getArrayMap(sqlInfoConstraintsFields, []any{}, nil)

		if err != nil {
			return err
		}

		resultFieldsRef, err := dbSql.getArrayMap(sqlInfoConstraintsFieldsRef, []any{}, nil)

		if err != nil {
			return err
		}

		for schemaName, schema := range schemas {
			schema.ForeignKeys = map[string]ForeignKey{}
			tableName := CamelToUnderscore(schemaName)

			for _, constraint := range result {
				if strings.TrimSpace(strings.ToLower(constraint["tableName"].(string))) != tableName {
					continue
				}

				if constraint["constraintName"] == "" {
					continue
				}

				constraintName := strings.TrimSpace(constraint["constraintName"].(string))
				name := UnderscoreToCamel(strings.ToLower(constraintName), false)
				list := []map[string]any{}
				for _, item := range resultFields {
					if strings.TrimSpace(item["constraintName"].(string)) == constraintName {
						list = append(list, item)
					}
				}

				listRef := []map[string]any{}
				for _, item := range resultFieldsRef {
					if strings.TrimSpace(item["constraintName"].(string)) == constraintName {
						listRef = append(listRef, item)
					}
				}

				constraintType := strings.TrimSpace(constraint["constraintType"].(string))

				if constraintType == "FOREIGN KEY" {
					foreignKey := ForeignKey{Fields: []string{}, FieldsRef: []string{}}

					for _, item := range list {
						foreignKey.Fields = append(foreignKey.Fields, getFieldName(item["columnName"].(string), nil))
					}

					for _, itemRef := range listRef {
						foreignKey.FieldsRef = append(foreignKey.FieldsRef, getFieldName(itemRef["columnName"].(string), nil))
						tableRef := UnderscoreToCamel(strings.ToLower(itemRef["tableName"].(string)), false)

						if foreignKey.TableRef == "" || foreignKey.TableRef == tableRef {
							foreignKey.TableRef = tableRef
						} else {
							log.Printf(`[${dbSql.constructor.name}.getOpenApi().processConstraints()] : tableRef already defined : new (${tableRef}, old (${foreignKey.tableRef}))`)
						}
					}

					if len(foreignKey.Fields) != len(foreignKey.FieldsRef) {
						log.Printf(`[${dbSql.constructor.name}.getOpenApi().processConstraints()] : fields and fieldsRef length don't match : fields (${foreignKey.fields.toString()}, fieldsRef (${foreignKey.fieldsRef.toString()}))`)
						continue
					}

					if len(foreignKey.Fields) == 1 {
						setRef(schema, foreignKey.Fields[0], foreignKey.TableRef)
						continue
					}

					if len(foreignKey.Fields) > 1 && slices.Index(foreignKey.Fields, foreignKey.TableRef) >= 0 {
						setRef(schema, foreignKey.TableRef, foreignKey.TableRef)
					}

					schema.ForeignKeys[name] = foreignKey
				} else if constraintType == "UNIQUE" {
					schema.UniqueKeys[name] = []string{}

					for _, item := range list {
						fieldName := getFieldName(item["columnName"].(string), nil)

						if slices.Index(schema.UniqueKeys[name], fieldName) < 0 {
							schema.UniqueKeys[name] = append(schema.UniqueKeys[name], fieldName)
						}
					}
				} else if constraintType == "PRIMARY KEY" {
					for _, item := range list {
						fieldName := getFieldName(item["columnName"].(string), nil)

						if slices.Index(schema.PrimaryKeys, fieldName) < 0 {
							schema.PrimaryKeys = append(schema.PrimaryKeys, fieldName)
						}

						if slices.Index(schema.Required, fieldName) < 0 {
							schema.Required = append(schema.Required, fieldName)
						}
					}
				}
			}

			for name, foreignKey := range schema.ForeignKeys {
				candidates := []string{}

				for _, fieldName := range foreignKey.Fields {
					if field, ok := schema.Properties[fieldName]; ok && field.Ref == "" {
						candidates = append(candidates, fieldName)
					}
				}

				if len(candidates) == 1 {
					setRef(schema, candidates[0], foreignKey.TableRef)
					delete(schema.ForeignKeys, name)
				}
			}

			if list, ok := dbSql.missingPrimaryKeys[schemaName]; ok {
				for _, columnName := range list {
					if slices.Index(schema.PrimaryKeys, columnName) < 0 {
						schema.PrimaryKeys = append(schema.PrimaryKeys, columnName)
					}

					if slices.Index(schema.Required, columnName) < 0 {
						schema.Required = append(schema.Required, columnName)
					}
				}
			}

			if list, ok := dbSql.missingForeignKeys[schemaName]; ok {
				for fieldName, tableRef := range list {
					setRef(schema, fieldName, tableRef)
				}
			}

			if len(schema.Required) == 0 {
				log.Printf(`[${dbSql.constructor.name}.getOpenApi().processColumns()] missing required fields of table ${schemaName}`)
			}
		}

		return nil
	}

	processColumns := func() (map[string]*Schema, error) {
		dbSql.sqlTypes = []string{"boolean", "character varying", "character", "integer", "jsonb", "jsonb array", "numeric", "timestamp without time zone", "timestamp with time zone", "time without time zone", "bigint", "smallint", "text", "date", "double precision", "bytea"}
		dbSql.rufsTypes = []string{"boolean", "string", "string", "integer", "object", "array", "number", "date-time", "date-time", "date-time", "integer", "integer", "string", "date-time", "number", "string"}
		sqlInfoTables := `
		select 
		c.data_type,
		c.udt_name,
		c.table_name,
		c.column_name,
		c.is_nullable,
		c.is_updatable,
		COALESCE(c.numeric_scale, 0) as numeric_scale,
		COALESCE(c.numeric_precision, 0) as numeric_precision,
		COALESCE(c.character_maximum_length, 0) as character_maximum_length,
		COALESCE(c.column_default, '') as column_default,
		COALESCE(c.identity_generation, '') as identity_generation,
		left(COALESCE(pgd.description, ''),100) as description
		from pg_catalog.pg_statio_all_tables as st
		inner join pg_catalog.pg_description pgd on (pgd.objoid=st.relid)
		right outer join information_schema.columns c on (pgd.objsubid=c.ordinal_position and c.table_schema=st.schemaname and c.table_name=st.relname)
		where table_schema = 'public' order by c.table_name,c.ordinal_position
		`
		rows, err := dbSql.client.Query(sqlInfoTables)

		if err != nil {
			return nil, err
		}

		schemas := map[string]*Schema{}

		for rows.Next() {
			rec, _ := dbSql.getMapFromRow(rows, nil)
			sqlType := strings.ToLower(strings.Trim(rec["dataType"].(string), " "))
			sqlSubType := strings.ToLower(strings.Trim(rec["udtName"].(string), " "))

			if sqlType == "array" && sqlSubType == "_jsonb" {
				sqlType = "jsonb array"
			}

			typeIndex := slices.Index(dbSql.sqlTypes, sqlType)

			if typeIndex < 0 {
				log.Printf(`DbClientPostgres.getTablesInfo().processColumns() : Invalid Database Type : ${rec["dataType"].trim().toLowerCase()}, full rec : ${JSON.stringify(rec)}`)
				continue
			}

			tableName := UnderscoreToCamel(rec["tableName"].(string), false)

			if schemas[tableName] == nil {
				schemas[tableName] = &Schema{Type: "object", Properties: map[string]*Schema{}, UniqueKeys: map[string][]string{}}
			}

			schema := schemas[tableName]
			field := &Schema{}
			fieldName := getFieldName(rec["columnName"].(string), field)
			field.UniqueKeys = nil
			field.Type = dbSql.rufsTypes[typeIndex] // LocalDateTime,ZonedDateTime,Date,Time

			if field.Type == "date-time" {
				field.Type = "string"
				field.Format = "date-time"
			}

			field.Nullable = rec["isNullable"] == "YES" || rec["isNullable"] == 1    // true,false
			field.Updatable = rec["isUpdatable"] == "YES" || rec["isUpdatable"] == 1 // true,false
			field.Scale = int(rec["numericScale"].(int64))                           // > 0 // 3,2,1
			field.Precision = int(rec["numericPrecision"].(int64))                   // > 0
			if rec["columnDefault"] != nil {
				field.Default = rec["columnDefault"].(string) // 'pt-br'::character varying
			}
			if rec["description"] != nil {
				field.Description = rec["description"].(string)
			}

			if field.Nullable != true {
				if slices.Index(schema.Required, fieldName) < 0 {
					schema.Required = append(schema.Required, fieldName)
				}

				field.Essential = true
			}

			if strings.HasPrefix(sqlType, "character") == true {
				field.MaxLength = int(rec["characterMaximumLength"].(int64)) // > 0 // 255
			}

			if field.Type == "number" && field.Scale == 0 {
				field.Type = "integer"
			}

			if field.Default != "" && field.Default[:1] == "'" && len(field.Default) > 2 {
				posEnd := strings.LastIndex(field.Default, "'")

				if field.Type == "string" && posEnd > 1 {
					field.Default = field.Default[1:posEnd]
				} else {
					field.Default = ""
				}
			}

			if (field.Type == "integer" || field.Type == "number") && len(field.Default) > 0 {
				if _, err := strconv.ParseFloat(field.Default, 64); err != nil {
					field.Default = ""
				}
			}

			if rec["identityGeneration"] != nil {
				field.IdentityGeneration = rec["identityGeneration"].(string)
			}
			// SERIAL TYPE
			if strings.HasPrefix(field.Default, "nextval") {
				field.IdentityGeneration = "BY DEFAULT"
			}

			if field.Type == "array" {
				field.Items = &Schema{}
			}

			schema.Properties[fieldName] = field
		}

		return schemas, nil
	}

	schemas, _ := processColumns()
	processConstraints(schemas)
	options.schemas = schemas
	dbSql.openapi = openapi
	openapi.FillOpenApi(options)
	return nil
}

func (dbSql *DbClientSql) CreateTable(name string, schema *Schema) (sql.Result, error) {
	genSqlColumnDescription := func(fieldName string, field *Schema) (string, error) {
		if field.Type == "" {
			if field.IdentityGeneration != "" {
				field.Type = "integer"
			} else {
				field.Type = "string"
			}
		}

		pos := slices.Index(dbSql.rufsTypes, field.Type)

		if pos < 0 {
			return "", fmt.Errorf(`[CreateTable(%s).genSqlColumnDescription(%s)] Missing rufsType equivalent of %s`, name, fieldName, field.Type)
		}

		sqlType := dbSql.sqlTypes[pos]

		if field.Type == "string" && field.MaxLength > 0 && field.MaxLength < 32 {
			sqlType = "character"
		}

		if field.MaxLength == 0 {
			if field.Type == "string" {
				field.MaxLength = 255
			}
			if field.Type == "number" {
				field.MaxLength = 9
			}
		}

		if field.Type == "number" && field.Scale == 0 {
			field.Scale = 3
		}

		sqlLengthScale := ""

		if field.MaxLength != 0 && field.Scale != 0 {
			sqlLengthScale = fmt.Sprintf(`(%d,%d)`, field.MaxLength, field.Scale)
		} else if field.MaxLength != 0 {
			sqlLengthScale = fmt.Sprintf(`(%d)`, field.MaxLength)
		}

		sqlDefault := ""

		if field.IdentityGeneration != "" {
			sqlDefault = fmt.Sprintf(`GENERATED %s AS IDENTITY`, field.IdentityGeneration)
			sqlType = `int`
		}

		if field.Default != "" {
			if field.Type == "string" {
				sqlDefault = fmt.Sprintf(` DEFAULT '%s'`, field.Default)
			} else {
				sqlDefault = " DEFAULT " + field.Default
			}
		}

		sqlNotNull := ""
		if field.Nullable != true {
			sqlNotNull = "NOT NULL"
		}
		return fmt.Sprintf(`%s %s%s %s %s`, CamelToUnderscore(fieldName), sqlType, sqlLengthScale, sqlDefault, sqlNotNull), nil
	}
	// TODO : refatorar função genSqlForeignKey(fieldName, field) para genSqlForeignKey(tableName)
	genSqlForeignKey := func(fieldName string, field *Schema) string {
		ref := OpenApiGetSchemaName(field.Ref)
		tableOut := CamelToUnderscore(ref)
		return fmt.Sprintf(`FOREIGN KEY(%s) REFERENCES %s`, CamelToUnderscore(fieldName), tableOut)
	}

	tableBody := ""
	for fieldName, field := range schema.Properties {
		fieldDescription, err := genSqlColumnDescription(fieldName, field)

		if err != nil {
			return nil, err
		}

		tableBody = tableBody + fieldDescription + ", "
	}
	// add foreign keys
	for fieldName, field := range schema.Properties {
		if field.Ref != "" {
			tableBody = tableBody + genSqlForeignKey(fieldName, field) + ", "
		}
	}
	// add primary key
	tableBody = tableBody + `PRIMARY KEY(`
	for _, fieldName := range schema.PrimaryKeys {
		tableBody = tableBody + CamelToUnderscore(fieldName) + `, `
	}
	tableBody = tableBody[:len(tableBody)-2] + `)`
	tableName := CamelToUnderscore(name)
	sql := fmt.Sprintf(`CREATE TABLE %s (%s)`, tableName, tableBody)
	fmt.Printf("entityManager.createTable() : table %s, sql : \n%s\n", name, sql)
	result, err := dbSql.client.Exec(sql)

	if err != nil {
		return nil, err
	}

	err = dbSql.UpdateOpenApi(dbSql.openapi, FillOpenApiOptions{requestBodyContentType: dbSql.dbConfig.requestBodyContentType})

	return result, err
}
*/
}

#[tide::utils::async_trait]
impl EntityManager for DbAdapterPostgres {
    fn insert(&self, _openapi: &OpenAPI, table_name :&str, obj :&Value) -> Result<Value, Error> {
        println!("[DbAdapterPostgres.find({}, {})]", table_name, obj.to_string());
        Ok(obj.clone())
    }

    fn find_one(self: &Self, table: &str, key: &Value) -> Option<Box<Value>> {
        println!("[DbAdapterPostgres.find_one({}, {})]", table, key);
        //let list = self.find(table, key, vec![]);
        None
    }

    async fn find(self: &Self, table: &str, _key: &Value, _order_by: &Vec<String>) -> Vec<Value> {
        let list = self.client.as_ref().unwrap().query(format!("SELECT * FROM {}", table).as_str(), &[]).await.unwrap();
        return self.get_json_list(&list);
    }

    fn update<'a>(&'a self, table_name :&str, key :&Value, obj :&'a Value) -> Result<&'a Value, Error> {
        println!("[DbAdapterPostgres.find({}, {}, {})]", table_name, key, obj.to_string());
        Ok(&self.tmp)
    }

    fn delete_one(self: &Self, table_name: &str, key: &Value) -> Result<(), Error> {
        println!("[DbAdapterPostgres.delete_one({}, {})]", table_name, key);
        Ok(())
    }
}
