import sqlite3
from datetime import datetime


# Press Mayús+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
path_db = "/home/fernan/Documentos/Analisis_logs/proyectoDJ/logs_analysis/db.sqlite3"
path_log_kerio = "/home/fernan/Escritorio/http.log.txt"
path_log_squid = "/home/fernan/Escritorio/access_gprs_epepcentro.log.20210801"

# Crea un objeto de conexión a la base de datos SQLite
conn = sqlite3.connect(path_db)
# Con la conexión, crea un objeto cursor
c = conn.cursor()


def create_table(name_table, first_raw):
    c.execute("CREATE TABLE IF NOT EXISTS " + name_table + first_raw + ")")


def data_entry(name_table, data):
    c.execute("INSERT INTO " + name_table + "VALUES(" + data + ")")
    conn.commit()


def enterKerio(path_log_kerio):
    # Crea un objeto de conexión a la base de datos SQLite
    conn1 = sqlite3.connect(path_db)
    # Con la conexión, crea un objeto cursor
    c1 = conn1.cursor()
    file_log_kerio = open(path_log_kerio)
    count = 0
    for line_log in file_log_kerio:
        line_split = line_log.split()
        ip = line_split[0]
        user = line_split[2]
        fecha = line_split[3][1:]
        zona_horario = line_split[4][:-1]
        metodo = line_split[5][1:]
        url = line_split[6]
        protocolo = line_split[7][:-1]
        code_request = line_split[8]
        size_transf = line_split[9]

        # El resultado de "cursor.execute" puede ser iterado por fila
        c1.execute('''PRAGMA synchronous = OFF''')
        c1.execute("insert into analysis_squid_kerio_logskerio(ip_addres,user_name,date_time,time_zone,http_method,url,version_http,code_http,size_transfered,count_requests_transferred) "
                  "values (?,?,?,?,?,?,?,?,?,?)", (str(ip), str(user), datetime.strptime(fecha, '%d/%b/%Y:%H:%M:%S'), str(zona_horario), str(metodo), str(url), str(protocolo), str(code_request), str(size_transf), "No asignado"))
        conn1.commit()
        count += 1
        print("\r Lineas guardadas de Kerio: " + str(count), end="", flush=True)

    #for row in c.execute('SELECT * FROM analysis_squid_kerio_logskerio;'): str(fecha)
    #     print(row)

        #break

    # No te olvides de cerrar la conexión
    print("\n")
    conn1.close()

def enterSquid(path_squid):
    # Crea un objeto de conexión a la base de datos SQLite
    conn2 = sqlite3.connect(path_db)
    # Con la conexión, crea un objeto cursor
    c2 = conn2.cursor()
    file_log_squid = open(path_squid)
    count = 0
    for line_log_squid in file_log_squid:
        line_split = line_log_squid.split()
        #print(line_split)

        date_time = line_split[0]
        time_request = line_split[1]
        ip_client = line_split[2]
        cache_result_code = line_split[3]
        size_transfered = line_split[4]
        http_method = line_split[5]
        url = line_split[6]
        user_name = line_split[7]
        request_server_name = line_split[8]
        content_type = line_split[9]

        # print("time_request: " + str(time_request))
        # print("ip_client: " + str(ip_client))
        # print("cache_result_code: " + str(cache_result_code))
        # print("size_transfered: " + str(size_transfered))
        # print("http_method: " + str(http_method))
        # print("url: " + str(url))
        # print("user_name: " + str(user_name))
        # print("request_server_name: " + str(request_server_name))
        # print("contenido: " + content_type)

        date_time1 = datetime.fromtimestamp(float(date_time.partition(".")[0]))
        date_time2 = datetime.strptime(str(date_time1), '%Y-%m-%d %H:%M:%S')
        # if date_time.count(".") == 1:
        #     #print("ip un punto: " + str(ip_client))
        #     print("fecha stam: " + str(date_time))
        #     print("fecha date_time1: " + str(date_time1))
        #     date_time2 = datetime.strptime(str(date_time1), '%Y-%m-%d %H:%M:%S.%f')
        # if date_time.count(".") == 0:
        #     print("fecha stam sin punto: " + str(date_time))
        #     print(str(ip_client))
        #     print(str(date_time))
        #     date_time2 = datetime.strptime(str(date_time1), '%Y-%m-%d %H:%M:%S')
        # print("Fecha timestamp: " + str(float(date_time)))
        # print("fecha: " + str(date_time2))
        # print("cant de . : " + str(date_time.count(".")))

        # El resultado de "cursor.execute" puede ser iterado por fila
        c2.execute('''PRAGMA synchronous = OFF''')
        c2.execute("insert into analysis_squid_kerio_logssquid(date_time, time_request, ip_client, cache_result_code, size_transfered, http_method, url, "
                  "user_name, request_server_name, content_type, time_stamp)" 
                  "values (?,?,?,?,?,?,?,?,?,?,?)", (str(date_time2), str(time_request), str(ip_client), str(cache_result_code), str(size_transfered), str(http_method),
                                                   str(url), str(user_name), str(request_server_name), str(content_type), str(date_time)))
        conn2.commit()
        #print("prueba" + str(count), end="/")
        count += 1
        print("\r Lineas guardadas de Squid: " + str(count), end="", flush=True)
        #print('Linea ingresada: '+ str(count) , end = "")
        #print('Descargando el archivo FooFile.txt [% d %%] \ r'% count, end = "")
        #break
    print("\n")
    conn2.close()

def enterDomainBlackList(path_black_list, category):
    # Crea un objeto de conexión a la base de datos SQLite
    conn1 = sqlite3.connect(path_db)
    # Con la conexión, crea un objeto cursor
    c1 = conn1.cursor()
    file_Black_list = open(path_black_list)
    count = 0
    fecha = datetime.today()
    for line_domain in file_Black_list:
        domain = line_domain[0:-1]
        # line_split = line_log.split()
        # ip = line_split[0]
        # user = line_split[2]
        # fecha = line_split[3][1:]
        # zona_horario = line_split[4][:-1]
        # metodo = line_split[5][1:]
        # url = line_split[6]
        # protocolo = line_split[7][:-1]
        # code_request = line_split[8]
        # size_transf = line_split[9]
        c1.execute('''PRAGMA synchronous = OFF''')
        c1.execute(
            "insert into analysis_squid_kerio_blacklistdomain(fecha_entrada,domain,category) "
            "values (?,?,?)", (
            fecha, str(domain), category))
        # El resultado de "cursor.execute" puede ser iterado por fila

        conn1.commit()
        count = +1

        print("\r Lineas guardadas de 'Black List': " + str(count), end="", flush=True)

    # for row in c.execute('SELECT * FROM analysis_squid_kerio_logskerio;'): str(fecha)
    #     print(row)

    # break

    # No te olvides de cerrar la conexión
    print("\n")
    conn1.close()




#---------------------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------------------

while True:
    print("Seleccione que tipo de log va entrar")
    print(" 'K': para Kerio ")
    print(" 'S': para Squid ")

    print(" 'T': para Squid y Kerio")

    print(" 'BL': para entrar Black List")

    print("Presione ESPACIO + ENTER para salir")
    letra = input()
    if letra == " ":
        break

    if letra.lower() == "t":
        print("Entre dir de log Kerio")
        path_log_kerio = input()

        print("Entre dir de log Squid")
        path_log_squid = input()

        print("Se comenzara a entrar los log Squid y Kerio a la Base de Datos")
        enterKerio(path_log_kerio)
        enterSquid(path_log_squid)

    if letra.lower() == "k":
        print("Entre dir de log Kerio")
        path_log_kerio = input()
        print("Se comenzara a entrar los log Kerio a la Base de Datos")
        enterKerio(path_log_kerio)
    if letra.lower() == "s":
        print("Entre dir de log Squid")
        path_log_squid = input()
        print("Se comenzara a entrar los log Squid a la Base de Datos")
        enterSquid(path_log_squid)
    if letra.lower() == "bl":
        print("Entre dir del archivo de la Black List")
        path_black_list = input()
        print("Entre la categoria a la que pertenecen")
        category = input()
        print("Se comenzara a entrar los dominios prohibidos de la Black List")
        enterDomainBlackList(path_black_list, category)

#enterKerio(path_log_kerio)
#enterSquid(path_log_squid)