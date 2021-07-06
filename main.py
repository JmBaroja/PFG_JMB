### Librerias, recursos y conexiones necesarias
import requests
from bs4 import BeautifulSoup
import mysql.connector
import datetime
import pickle
from switch import Switch

class Attack:

    borrado = False

    def __init__(self, id, size, clas, dst, maxbps, src, start, stop, subclas):
        self.id = id
        self.size = size
        self.clas = clas
        self.dst = dst
        self.maxbps = maxbps
        self.src = src
        self.start = start
        self.stop = stop
        self.subclas = subclas

    def __str__(self):
        return "{} {} {} {} {} {} {} {} {}".format(
            self.id, self.size, self.clas, self.dst, self.maxbps, self.src, self.start, self.stop, self.subclas)

class ListAtt:

    attacks = []
    vacio = True
    info = {
        'newest': 0,
        'counter': 1,
        'inserted': 0
    }

    def __init__(self):
        att_save = open("attacks", "ab+")
        att_save.seek(0)
        info_save = open("info", "ab+")
        info_save.seek(0)
        try:
            self.attacks = pickle.load(att_save)
            self.info = pickle.load(info_save)
            self.vacio = False
            print("Se cargaron {} ataques del fichero externo".format(len(self.attacks)))
            print("Se detectaron {} ataques insertados en la BBDD y el ataque más reciente es del {}".format(self.getInserted(), datetime.datetime.fromtimestamp(self.getNewest())))
        except:
            print("El fichero está vacío")
        finally:
            att_save.close()
            info_save.close()
            del(att_save)
            del(info_save)

    def getNewest(self):
        return self.info["newest"]

    def setNewest(self, newest):
        self.info["newest"] = newest

    def getCounter(self):
        return self.info["counter"]

    def setCounter(self):
        self.info["counter"] = self.info["counter"]+1

    def getInserted(self):
        return self.info["inserted"]

    def setInserted(self):
        self.info["inserted"] = self.info["inserted"] + 1

    def printAttacks(self):
        for a in self.attacks:
            print(a)

    def saveAttacks(self):
        att_save = open("attacks", "wb")
        info_save = open("info", "wb")
        pickle.dump(self.attacks, att_save)
        pickle.dump(self.info, info_save)
        att_save.close()
        info_save.close()
        del(att_save)
        del(info_save)

db = mysql.connector.connect(
    host="localhost",
    user="root",
    passwd="root"
)
mycursor = db.cursor()



### Carga todos los datos de ciberataques DDOS de la página mencionada
def get_data():
    headers = {
        'authority': 'www.gstatic.com',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="90", "Google Chrome";v="90"',
        'sec-ch-ua-mobile': '?0',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36',
        'accept': '*/*',
        'origin': 'https://www.digitalattackmap.com',
        'x-client-data': 'CJW2yQEIprbJAQjEtskBCKmdygEI+MfKAQioncsBCKCgywEIv6DLAQjd8ssBCKjzywE=',
        'sec-fetch-site': 'cross-site',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://www.digitalattackmap.com/',
        'accept-language': 'es-ES,es;q=0.9,en;q=0.8',
    }

    response = requests.get('https://www.gstatic.com/ddos-viz/attacks_v2.json', headers=headers)
    return response.json()

### Crea db y tablas del sql
def set_ddbb():
    mycursor.execute("DROP DATABASE IF EXISTS TFG_JMB")
    mycursor.execute("CREATE DATABASE IF NOT EXISTS TFG_JMB")
    mycursor.execute("USE TFG_JMB")
    mycursor.execute(
        "CREATE TABLE IF NOT EXISTS Tipo_Ataque (ID_T INT NOT NULL AUTO_INCREMENT,Tipo VARCHAR(20) NOT NULL,Subtipo VARCHAR(20) NOT NULl,PRIMARY KEY (ID_T))")
    mycursor.execute(
        "CREATE TABLE IF NOT EXISTS Pais_Info (ID_P INT NOT NULL AUTO_INCREMENT,Abreviatura VARCHAR(2),Nombre VARCHAR(100) NOT NULL,PRIMARY KEY (ID_P))")
    mycursor.execute(
        "CREATE TABLE IF NOT EXISTS Ciberataques (ID_CA INT NOT NULL AUTO_INCREMENT,Tamaño VARCHAR(8) NOT NULL,Tipo INT NOT NULL,Origen VARCHAR(500) NOT NULL,Destino VARCHAR(500) NULL,Max_Bps FLOAT(15,0) NOT NULL,PRIMARY KEY (ID_CA),FOREIGN KEY (Tipo) REFERENCES Tipo_Ataque(ID_T) ON UPDATE CASCADE)")
    mycursor.execute(
        "CREATE TABLE IF NOT EXISTS Fecha_Ataque (ID_F INT NOT NULL,Fecha_Ini DATETIME NOT NULL,Fecha_Fin DATETIME NOT NULL,FOREIGN KEY (ID_F) REFERENCES Ciberataques(ID_CA) ON UPDATE CASCADE)")
    mycursor.execute(
        "CREATE TABLE IF NOT EXISTS Historial (ID_H INT NOT NULL AUTO_INCREMENT,ID_P INT,NAtacados INT,NRecibidos INT NOT NULL,At2021 INT,Re2021 INT,At2020 INT,Re2020 INT,At2019 INT,Re2019 INT,At2018 INT,Re2018 INT,At2017 INT,Re2017 INT,At2016 INT,Re2016 INT,At2015 INT,Re2015 INT,PRIMARY KEY (ID_H),FOREIGN KEY (ID_P) REFERENCES Pais_Info(ID_P) ON UPDATE CASCADE)")

    mycursor.execute("""
        CREATE PROCEDURE INS_HIST()
           BEGIN
              SET @id = 1 ;
              for_loop: LOOP
                 INSERT INTO Historial (ID_P,NAtacados,NRecibidos) VALUES (
                     @id,
                     (SELECT COUNT(ID_CA) as NAtacados 
                     FROM Ciberataques 
                     WHERE Origen LIKE CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') 
                     AND Origen <> 'Desconocido'), 
                     (SELECT COUNT(ID_CA) as NRecibidos 
                     FROM Ciberataques 
                     WHERE Destino LIKE CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') 
                     AND Destino <> 'Desconocido')
                 );
                 
                 SET @id=@id+1;
                 IF @id>252 THEN
                    INSERT INTO Pais_Info (Abreviatura,Nombre) VALUES (null,'Desconocido');
                    INSERT INTO Historial (ID_P,NAtacados,NRecibidos) VALUES (@id,
                    (SELECT COUNT(ID_CA) as NAtacados FROM Ciberataques WHERE Origen = 'Desconocido'), 
                    (SELECT COUNT(ID_CA) as NRecibidos FROM Ciberataques WHERE Destino = 'Desconocido'));
                    LEAVE for_loop;
                 END IF;
            END LOOP for_loop;
        END
    """)
    mycursor.execute("""
            CREATE PROCEDURE UPD_HIST()
                BEGIN
                      SET @id = 1 ;
                      for_loop: LOOP
                         UPDATE Historial SET NAtacados=
                             (SELECT COUNT(ID_CA) as NAtacados 
                             FROM Ciberataques 
                             WHERE Origen LIKE CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') 
                             AND Origen <> 'Desconocido'), 
                             NRecibidos=
                             (SELECT COUNT(ID_CA) as NRecibidos 
                             FROM Ciberataques 
                             WHERE Destino LIKE CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') 
                             AND Destino <> 'Desconocido')
                         WHERE ID_P=@id;
                         
                         SET @id=@id+1;
                         IF @id>252 THEN
                            UPDATE Historial SET 
                            NAtacados= (SELECT COUNT(ID_CA) as NAtacados FROM Ciberataques WHERE Origen = 'Desconocido'), 
                            NRecibidos=(SELECT COUNT(ID_CA) as NRecibidos FROM Ciberataques WHERE Destino = 'Desconocido')
                            WHERE ID_P=@id;
                            LEAVE for_loop;
                         END IF;
                   END LOOP for_loop;
                END
        """)
    mycursor.execute("""
        CREATE PROCEDURE INS_A2021()
            BEGIN
                  SET @id = 1 ;
                  for_loop: LOOP
                     UPDATE Historial SET 
                         At2021=(SELECT count(ID_CA) FROM Ciberataques
                         inner join fecha_ataque ON id_f=id_ca
                         where (fecha_ini LIKE '%2021-%' OR fecha_fin LIKE '%2021-%')
                         AND origen like CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') AND Origen <> 'Desconocido'), 
                         Re2021=(SELECT count(ID_CA) FROM Ciberataques
                         inner join fecha_ataque ON id_f=id_ca
                         where (fecha_ini LIKE '%2021-%' OR fecha_fin LIKE '%2021-%')
                         AND Destino like CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') AND Destino <> 'Desconocido')
                     WHERE ID_H=@id;
                     
                     SET @id=@id+1;
                     IF @id>252 THEN
                        UPDATE Historial SET 
                        At2021= (SELECT COUNT(ID_CA) as At2021 FROM Ciberataques inner join fecha_ataque ON id_f=id_ca WHERE (fecha_ini LIKE '%2021-%' OR fecha_fin LIKE '%2021-%') AND Origen = 'Desconocido'), 
                        Re2021=(SELECT COUNT(ID_CA) as Re2021 FROM Ciberataques inner join fecha_ataque ON id_f=id_ca WHERE (fecha_ini LIKE '%2021-%' OR fecha_fin LIKE '%2021-%') AND Destino = 'Desconocido')
                        WHERE ID_P=@id;
                        LEAVE for_loop;
                     END IF;
               END LOOP for_loop;
            END
            """)
    mycursor.execute("""
        CREATE PROCEDURE INS_A2020()
           BEGIN
              SET @id = 1 ;
              for_loop: LOOP
                 UPDATE Historial SET 
                     At2020=(SELECT count(ID_CA) FROM Ciberataques
                     inner join fecha_ataque ON id_f=id_ca
                     where (fecha_ini LIKE '%2020-%' OR fecha_fin LIKE '%2020-%')
                     AND origen like CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') AND Origen <> 'Desconocido'), 
                     Re2020=(SELECT count(ID_CA) FROM Ciberataques
                     inner join fecha_ataque ON id_f=id_ca
                     where (fecha_ini LIKE '%2020-%' OR fecha_fin LIKE '%2020-%')
                     AND Destino like CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') AND Destino <> 'Desconocido')
                 WHERE ID_H=@id;
                 
                 SET @id=@id+1;
                 IF @id>252 THEN
                    UPDATE Historial SET 
                    At2020= (SELECT COUNT(ID_CA) as At2020 FROM Ciberataques inner join fecha_ataque ON id_f=id_ca WHERE (fecha_ini LIKE '%2020-%' OR fecha_fin LIKE '%2020-%') AND Origen = 'Desconocido'), 
                    Re2020=(SELECT COUNT(ID_CA) as Re2020 FROM Ciberataques inner join fecha_ataque ON id_f=id_ca WHERE (fecha_ini LIKE '%2020-%' OR fecha_fin LIKE '%2020-%') AND Destino = 'Desconocido')
                    WHERE ID_P=@id;
                    LEAVE for_loop;
                 END IF;
           END LOOP for_loop;
        END
            """)
    mycursor.execute("""
        CREATE PROCEDURE INS_A2019()
           BEGIN
              SET @id = 1 ;
              for_loop: LOOP
                 UPDATE Historial SET 
                     At2019=(SELECT count(ID_CA) FROM Ciberataques
                     inner join fecha_ataque ON id_f=id_ca
                     where (fecha_ini LIKE '%2019-%' OR fecha_fin LIKE '%2019-%')
                     AND origen like CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') AND Origen <> 'Desconocido'), 
                     Re2019=(SELECT count(ID_CA) FROM Ciberataques
                     inner join fecha_ataque ON id_f=id_ca
                     where (fecha_ini LIKE '%2019-%' OR fecha_fin LIKE '%2019-%')
                     AND Destino like CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') AND Destino <> 'Desconocido')
                 WHERE ID_H=@id;
                 
                 SET @id=@id+1;
                 IF @id>252 THEN
                    UPDATE Historial SET 
                    At2019= (SELECT COUNT(ID_CA) as At2019 FROM Ciberataques inner join fecha_ataque ON id_f=id_ca WHERE (fecha_ini LIKE '%2019-%' OR fecha_fin LIKE '%2019-%') AND Origen = 'Desconocido'), 
                    Re2019=(SELECT COUNT(ID_CA) as Re2019 FROM Ciberataques inner join fecha_ataque ON id_f=id_ca WHERE (fecha_ini LIKE '%2019-%' OR fecha_fin LIKE '%2019-%') AND Destino = 'Desconocido')
                    WHERE ID_P=@id;
                    LEAVE for_loop;
                 END IF;
           END LOOP for_loop;
        END
            """)
    mycursor.execute("""
        CREATE PROCEDURE INS_A2018()
           BEGIN
              SET @id = 1 ;
              for_loop: LOOP
                 UPDATE Historial SET 
                     At2018=(SELECT count(ID_CA) FROM Ciberataques
                     inner join fecha_ataque ON id_f=id_ca
                     where (fecha_ini LIKE '%2018-%' OR fecha_fin LIKE '%2018-%')
                     AND origen like CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') AND Origen <> 'Desconocido'), 
                     Re2018=(SELECT count(ID_CA) FROM Ciberataques
                     inner join fecha_ataque ON id_f=id_ca
                     where (fecha_ini LIKE '%2018-%' OR fecha_fin LIKE '%2018-%')
                     AND Destino like CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') AND Destino <> 'Desconocido')
                 WHERE ID_H=@id;
                 
                 SET @id=@id+1;
                 IF @id>252 THEN
                    UPDATE Historial SET 
                    At2018= (SELECT COUNT(ID_CA) as At2018 FROM Ciberataques inner join fecha_ataque ON id_f=id_ca WHERE (fecha_ini LIKE '%2018-%' OR fecha_fin LIKE '%2018-%') AND Origen = 'Desconocido'), 
                    Re2018=(SELECT COUNT(ID_CA) as Re2018 FROM Ciberataques inner join fecha_ataque ON id_f=id_ca WHERE (fecha_ini LIKE '%2018-%' OR fecha_fin LIKE '%2018-%') AND Destino = 'Desconocido')
                    WHERE ID_P=@id;
                    LEAVE for_loop;
                 END IF;
           END LOOP for_loop;
        END
            """)
    mycursor.execute("""
        CREATE PROCEDURE INS_A2017()
           BEGIN
              SET @id = 1 ;
              for_loop: LOOP
                 UPDATE Historial SET 
                     At2017=(SELECT count(ID_CA) FROM Ciberataques
                     inner join fecha_ataque ON id_f=id_ca
                     where (fecha_ini LIKE '%2017-%' OR fecha_fin LIKE '%2017-%')
                     AND origen like CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') AND Origen <> 'Desconocido'), 
                     Re2017=(SELECT count(ID_CA) FROM Ciberataques
                     inner join fecha_ataque ON id_f=id_ca
                     where (fecha_ini LIKE '%2017-%' OR fecha_fin LIKE '%2017-%')
                     AND Destino like CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') AND Destino <> 'Desconocido')
                 WHERE ID_H=@id;
                 
                 SET @id=@id+1;
                 IF @id>252 THEN
                    UPDATE Historial SET 
                    At2017= (SELECT COUNT(ID_CA) as At2017 FROM Ciberataques inner join fecha_ataque ON id_f=id_ca WHERE (fecha_ini LIKE '%2017-%' OR fecha_fin LIKE '%2017-%') AND Origen = 'Desconocido'), 
                    Re2017=(SELECT COUNT(ID_CA) as Re2017 FROM Ciberataques inner join fecha_ataque ON id_f=id_ca WHERE (fecha_ini LIKE '%2017-%' OR fecha_fin LIKE '%2017-%') AND Destino = 'Desconocido')
                    WHERE ID_P=@id;
                    LEAVE for_loop;
                 END IF;
           END LOOP for_loop;
        END 
            """)
    mycursor.execute("""
        CREATE PROCEDURE INS_A2016()
        BEGIN
          SET @id = 1 ;
          for_loop: LOOP
             UPDATE Historial SET 
                 At2016=(SELECT count(ID_CA) FROM Ciberataques
                 inner join fecha_ataque ON id_f=id_ca
                 where (fecha_ini LIKE '%2016-%' OR fecha_fin LIKE '%2016-%')
                 AND origen like CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') AND Origen <> 'Desconocido'), 
                 Re2016=(SELECT count(ID_CA) FROM Ciberataques
                 inner join fecha_ataque ON id_f=id_ca
                 where (fecha_ini LIKE '%2016-%' OR fecha_fin LIKE '%2016-%')
                 AND Destino like CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') AND Destino <> 'Desconocido')
             WHERE ID_H=@id;
             
             SET @id=@id+1;
             IF @id>252 THEN
                UPDATE Historial SET 
                At2016= (SELECT COUNT(ID_CA) as At2016 FROM Ciberataques inner join fecha_ataque ON id_f=id_ca WHERE (fecha_ini LIKE '%2016-%' OR fecha_fin LIKE '%2016-%') AND Origen = 'Desconocido'), 
                Re2016=(SELECT COUNT(ID_CA) as Re2016 FROM Ciberataques inner join fecha_ataque ON id_f=id_ca WHERE (fecha_ini LIKE '%2016-%' OR fecha_fin LIKE '%2016-%') AND Destino = 'Desconocido')
                WHERE ID_P=@id;
                LEAVE for_loop;
             END IF;
        END LOOP for_loop;
        END
            """)
    mycursor.execute("""
        CREATE PROCEDURE INS_A2015()
           BEGIN
              SET @id = 1 ;
              for_loop: LOOP
                 UPDATE Historial SET 
                     At2015=(SELECT count(ID_CA) FROM Ciberataques
                     inner join fecha_ataque ON id_f=id_ca
                     where (fecha_ini LIKE '%2015-%' OR fecha_fin LIKE '%2015-%')
                     AND origen like CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') AND Origen <> 'Desconocido'), 
                     Re2015=(SELECT count(ID_CA) FROM Ciberataques
                     inner join fecha_ataque ON id_f=id_ca
                     where (fecha_ini LIKE '%2015-%' OR fecha_fin LIKE '%2015-%')
                     AND Destino like CONCAT('%', (select Abreviatura from pais_info where id_p=@id), '%') AND Destino <> 'Desconocido')
                 WHERE ID_H=@id;
                 
                 SET @id=@id+1;
                 IF @id>252 THEN
                    UPDATE Historial SET 
                    At2015= (SELECT COUNT(ID_CA) as At2015 FROM Ciberataques inner join fecha_ataque ON id_f=id_ca WHERE (fecha_ini LIKE '%2015-%' OR fecha_fin LIKE '%2015-%') AND Origen = 'Desconocido'), 
                    Re2015=(SELECT COUNT(ID_CA) as Re2015 FROM Ciberataques inner join fecha_ataque ON id_f=id_ca WHERE (fecha_ini LIKE '%2015-%' OR fecha_fin LIKE '%2015-%') AND Destino = 'Desconocido')
                    WHERE ID_P=@id;
                    LEAVE for_loop;
                 END IF;
           END LOOP for_loop;
        END
                """)
    mycursor.execute("""
        CREATE PROCEDURE EXC_PRO()
            BEGIN
                SET @nuevo = (SELECT SUM(NAtacados) FROM Historial);
                IF @nuevo>0
                    THEN CALL UPD_HIST;
                    ELSE CALL INS_HIST;
                END IF;
                CALL INS_A2021;
                CALL INS_A2020;
                CALL INS_A2019;
                CALL INS_A2018;
                CALL INS_A2017;
                CALL INS_A2016;
                CALL INS_A2015;
            END
    """)

    print("BASE DE DATOS CREADA CORRECTAMENTE")

### Crea el listado correspondiente entre abreviaturas y nombre del pais
def set_countries():
    url = 'https://laendercode.net/es/2-letter-list.html'
    page = requests.get(url)
    soup = BeautifulSoup(page.content, 'html.parser')
    sql = "INSERT INTO Pais_Info (Abreviatura, Nombre) VALUES (%s, %s)"

    abreviaturas = []
    nombres = []

    abr = soup.find_all('h4', 'margin-clear')
    for i in abr:
        nom = soup.find('a', href='https://laendercode.net/es/country/'+i.text.lower())
        abreviaturas.append(i.text)
        nombres.append(nom.text)

        val = (i.text, nom.text)
        mycursor.execute(sql, val)
        db.commit()

    mycursor.execute("INSERT INTO Pais_Info (Nombre) VALUES ('Desconocido')")
    mycursor.execute("SELECT COUNT(*) FROM Pais_Info")
    record = mycursor.fetchone()
    rec = ''.join([str(i) for i in record])
    print(rec, "records inserted.")

### Se usa para comprobar si se repiten los parametros en las listas correspondientes
def not_repeat (lista1, lista2, param1, param2):
    repetido = 0

    for i in lista1:
        if repetido == 1:
            break
        if i == param1:
            for j in lista2:
                if j == param2:
                    repetido = 1

    return repetido

### Guarda todos los ataques en un array tipo Attack
def set_attacks_class(data, la):
    lista1 = data["biggest"]
    size1 = "biggest"
    for item in lista1:
        if item == "attacks":
            for attr in lista1["attacks"]:
                src = ', '.join([str(i) for i in attr["src_cc"]])
                dst = ', '.join([str(i) for i in attr["dst_cc"]])
                if len(src) < 500 and len(dst) < 500:
                    aux = Attack(la.getCounter(), size1, attr["attack_class"], attr["dst_cc"], attr["max_bps"],
                                 attr["src_cc"], attr["start"], attr["stop"], attr["subclass"])
                    la.attacks.append(aux)
                    la.setCounter()
        if item == "newest_file":
            if la.getNewest() < lista1["newest_file"]:
                la.setNewest(lista1["newest_file"])

    lista2 = data["unusual"]
    size2 = "unusual"
    for item in lista2:
        if item == "attacks":
            for attr in lista2["attacks"]:
                src = ', '.join([str(i) for i in attr["src_cc"]])
                dst = ', '.join([str(i) for i in attr["dst_cc"]])
                if len(src) < 500 and len(dst) < 500:
                    aux = Attack(la.getCounter(), size2, attr["attack_class"], attr["dst_cc"], attr["max_bps"],
                                 attr["src_cc"], attr["start"], attr["stop"], attr["subclass"])
                    la.attacks.append(aux)
                    la.setCounter()
            if item == "newest_file":
                if la.getNewest() < lista2["newest_file"]:
                    la.setNewest(lista2["newest_file"])

    print("Se han insertado {} ataques en el fichero externo".format(len(la.attacks)))

### Crea el listado de la relacion de ataques tipo-subtipo
def set_types(att_list):
    tipo = []
    subtipo = []
    sql = "INSERT INTO Tipo_Ataque (Tipo, Subtipo) VALUES (%s, %s)"

    for item in att_list:
        if not_repeat(tipo, subtipo, item.clas, item.subclas) == 0:
            tipo.append(item.clas)
            subtipo.append(item.subclas)

            val = (item.clas, item.subclas)
            mycursor.execute(sql, val)
            db.commit()

    mycursor.execute("SELECT COUNT(*) FROM Tipo_Ataque")
    record = mycursor.fetchone()
    rec = ''.join([str(i) for i in record])
    print(rec, "records inserted.")

### Crea e inserta en la bbdd el listado de fechas de los ataques
def set_fecha(att_list, desde, hasta):
    sql = "INSERT INTO Fecha_Ataque (ID_F, Fecha_Ini, Fecha_Fin) VALUES (%s, %s, %s)"

    for item in att_list[desde:hasta]:
            inicio = datetime.datetime.fromtimestamp(item.start)
            final = datetime.datetime.fromtimestamp(item.stop)

            val = (item.id, inicio, final)
            mycursor.execute(sql, val)
            db.commit()

    print(hasta-desde, "records inserted.")

### Crea e inserta en la bbdd el listado de ciberataques con sus datos
def set_ciberatt(la, desde, hasta):
    sql = "INSERT INTO Ciberataques (Tamaño, Tipo, Origen, Destino, Max_Bps) VALUES (%s, %s, %s, %s, %s)"

    for item in la.attacks[desde:hasta]:
        sql2 = "SELECT ID_T FROM tfg.Tipo_Ataque WHERE Tipo = %s AND Subtipo = %s"
        val2 = (item.clas, item.subclas)
        mycursor.execute(sql2, val2)
        record = mycursor.fetchone()
        tipo = ''.join([str(i) for i in record])

        src = ', '.join([str(i) for i in item.src])
        if src == "":
            src = "Desconocido"
        dst = ', '.join([str(i) for i in item.dst])
        if dst == "":
            dst = "Desconocido"

        val = (item.size, tipo, src, dst, item.maxbps)
        mycursor.execute(sql, val)
        db.commit()
        la.setInserted()

    print(hasta-desde, "records inserted.")

### Guarda todos los ataques NUEVOS en un array tipo Attack
def set_new_attacks(data, la):
    cond1 = (data["biggest"])["newest_file"] > la.getNewest()
    cond2 = (data["biggest"])["newest_file"] > la.getNewest()
    if cond1 or cond2:
        antiguo = la.getNewest()
        insbef = len(la.attacks)
        if cond1:
            la.setNewest((data["biggest"])["newest_file"])
            lista1 = (data["biggest"])["attacks"]
            size1 = "biggest"
            for item in lista1:
                if item["stop"] > antiguo:
                    src = ', '.join([str(i) for i in item["src_cc"]])
                    dst = ', '.join([str(i) for i in item["dst_cc"]])
                    if len(src) < 500 and len(dst) < 500:
                        aux = Attack(la.getCounter(), size1, item["attack_class"], item["dst_cc"], item["max_bps"],
                                     item["src_cc"], item["start"], item["stop"], item["subclass"])
                        la.attacks.append(aux)
                        la.setCounter()
        if cond2:
            if (data["unusual"])["newest_file"] > la.getNewest():
                la.setNewest((data["unusual"])["newest_file"])
            lista2 = (data["unusual"])["attacks"]
            size2 = "unusual"
            for item in lista2:
                if item["stop"] > antiguo:
                    src = ', '.join([str(i) for i in item["src_cc"]])
                    dst = ', '.join([str(i) for i in item["dst_cc"]])
                    if len(src) < 500 and len(dst) < 500:
                        aux = Attack(la.getCounter(), size2, item["attack_class"], item["dst_cc"], item["max_bps"],
                                     item["src_cc"], item["start"], item["stop"], item["subclass"])
                        la.attacks.append(aux)
                        la.setCounter()

        print("Se han insertado {} nuevos ataques en el fichero externo".format(len(la.attacks)-insbef))

    else:
        print("¡Los datos de ciberataques existentes en el fichero externo se encuentran actualizados!")



### CODIGO MAIN
la = ListAtt()
if la.vacio:
    data = get_data()
    set_attacks_class(data, la)
    set_ddbb()
    set_countries()
    set_types(la.attacks)
else:
    mycursor.execute("USE TFG_JMB")
    while True:
        print("¿Desea comprobar si existen nuevos datos en la fuente de datos? (s/n)")
        op = input()
        with Switch(op) as case:
            if case("s", "S"):
                data2 = get_data()
                set_new_attacks(data2, la)
                break
            if case("n", "N"):
                break
            if case.default:
                print("Ha introducido incorrectamente el parametro especificado. Por favor, vuelva a intentarlo.")

exitwh = False
while (not exitwh) & ((la.getCounter()-la.getInserted()) > 1):
    print("Introduzca número de ataques a descargar en la BBDD (Disponibles: {}):".format(la.getCounter()-la.getInserted()))
    while True:
        try:
            numataques = int(input())
            break
        except:
            print("El numero de ataques a descargar tiene que estar especificado en numeros enteros")
    if numataques > (la.getCounter()-la.getInserted()):
        numataques = (la.getCounter()-la.getInserted())
    desde = la.getInserted()
    set_ciberatt(la, desde, desde+numataques)
    set_fecha(la.attacks, desde, desde+numataques)
    mycursor.callproc("EXC_PRO")
    while (la.getCounter()-la.getInserted()) > 1:
        print("¿Desea insertar más datos en la BBDD? (s/n)")
        opt = input()
        with Switch(opt) as case:
            if case("s", "S"):
                break
            if case("n", "N"):
                exitwh = True
                break
            if case.default:
                print("Ha introducido incorrectamente el parametro especificado. Por favor, vuelva a intentarlo.")


la.saveAttacks()
