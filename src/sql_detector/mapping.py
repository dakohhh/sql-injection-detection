__all__ = "VECTOR_MAAPPINGS"

VECTOR_MAAPPINGS = {
    "'": "r0",
    "OR": "r1",
    "=": "r2",
    "LIKE": "r3",
    "SELECT": "r4",
    "CONVERT": "r5",
    "INT": "r6",
    "CHAR": "r7",
    "VARCHAR": "r8",
    "NVARCHAR": "r9",
    "&&": "r10",
    "AND": "r11",
    "ORDER BY": "r12",
    ";": "r13",
    "UNION": "r14",
    "UNION SELECT": "r15",
    "SHUTDOWN": "r16",
    "EXEC": "r17",
    "XP_CMDSHELL()": "r18",
    "SP_EXECWEBTASK()": "r19",
    "IF": "r20",
    "ELSE": "r21",
    "WAITFOR": "r22",
    "--": "r23",
    "ASCII()": "r24",
    "BIN()": "r25",
    "HEX()": "r26",
    "UNHEX()": "r27",
    "BASE64()": "r28",
    "DEC()": "r29",
    "ROT13()": "r30",
    "*": "r31",
    "<": "r32",
    ">": "r33",
    "VERSION": "r34",
    "V$VERSION": "r35",
    "INFORMATION_SCHEMA.TABLES": "r36",
    "INFORMATION_SCHEMA.COLUMNS": "r37",
    "ALL_TABLES": "r38",
    "SUBSTRING": "r39",
    "SUBSTR": "r40",
    "CASE": "r41",
    "DECLARE": "r42",
    "MASTER..XP_DIRTREE": "r43",
    "@P": "r44",
    "SLEEP": "r45",
    "LOAD_FILE": "r46",
    "||": "r47",
    "~": "r48",
    "CURRENT_USER()": "r49",
    "CONCAT": "r50",
    "DATABASE()": "r51",
    "+": "r52",
    "VERSION()": "r53",
    "#": "r54",
    "ADMIN": "r55",
    "/*": "r56",
    "\\\\": "r57",
    "BYPASS": "r58",
    "BLACKLISTING": "r59",
    "DROP": "r60",
    ")": "r61",
    "(": "r62",
    "COOKIE": "r63",
    "%S%S": "r64",
    "_": "r65",
    "*\\": "r66",
    "MYSQL SPECIAL SQL": "r67",
    "/**": "r68",
    "!": "r69",
    ".": "r70",
    "TRUE": "r71",
    "FALSE": "r72",
    "DBMS_LOCK.SLEEP": "r73",
    "END": "r74",
    "COLLATE": "r75",
    "MD5": "r76",
    "HAVING": "r77",
    "GROUP BY": "r78",
    "NULL": "r79",
    "1/0": "r80",
    "INSERT": "r81",
    "PING": "r82",
    "TABLE_SCHEMA": "r83",
    "SYSOBJECTS": "r84",
    "SYSCOLUMNS": "r85",
    "TMP_SYS_TMP": "r86",
    "}": "r87",
    "{": "r88",
    "BENCHMARK": "r89",
    "PG_SLEEP": "r90",
    "INJECTION": "r91",
    "MYSQL.USER": "r92",
    "SHA1": "r93",
    "USER()": "r94",
    "LOCKWORKSTATION()": "r95",
    "CREATE": "r96",
    "EXITPROCESS()": "r97",
    "PASSWORD()": "r98",
    "ENCODE()": "r99",
    "COMPRESS()": "r100",
    "ROW_COUNT()": "r101",
    "SCHEMA()": "r102",
    "ROWCOUNT()": "r103",
    "…": "r104",
    "BULK": "r105",
    "OPENROWSET": "r106",
    "OUTFILE": "r107",
    "SA": "r108",
    "“": "r109",
    "`": "r110",
    "all_tab_columns": "r111",
}







if __name__ == '__main__':

    # malicious_string = "-1++select+1,2,3,4,5,6,7,8,9, unionversion()"
    malicious_string = "-1++select+1,2,3,4,5,6,7,8,9, unionversion() SELECT"

    mask = []


    for key, value in VECTOR_MAAPPINGS.items():


        if key.lower() in malicious_string.lower():

            print(key)

            mask.append(value)

    print(mask)
        