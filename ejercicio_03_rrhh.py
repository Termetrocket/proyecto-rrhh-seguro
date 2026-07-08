# SISTEMA DE GESTIÓN DE EMPLEADOS - RRHH
# Programación Segura - Evaluación Unidad 4
# ==========================================
# INSTRUCCIONES:
# Este script gestiona la nómina de empleados usando listas con diccionarios.
# Analiza el código e identifica:
#   1. Vulnerabilidades de seguridad detectables con Bandit
#   2. Malas prácticas de código detectables con SonarQube
# Proponga las correcciones correspondientes.
#
# PILARES A ANALIZAR:
#   - CONFIDENCIALIDAD : Anonimización de datos, credenciales hardcodeadas, hash débil
#   - INTEGRIDAD       : Validación de contraseñas, command injection, yaml inseguro
#   - DISPONIBILIDAD   : Manejo de excepciones, control de acceso por rol

import os      #* Sistema 
import yaml    #* Orden¿
import subprocess #* para el subprocess.run
import secrets #* Codigos randoms seguros
import bcrypt #* Hasheo seguro
from dotenv import load_dotenv

load_dotenv() #* Conecta el .py con el .env

#  Variables|Listas importantes
empleados     = []
departamentos = []
usuarios_rrhh = []
id_empleado   = 0
id_dpto       = 0
id_usuario    = 0

#  Constantes printeables
SEPARADOR = "="*50
MSG_EMPLEADO_NO_ENCONTRADO = "Empleado no encontrado."
MSG_PRESIONE_ENTER = "\n\nPRESIONE ENTER PARA CONTINUAR"
MSG_INGRESE_OPCION = "INGRESE OPCIÓN: "
MSG_OPCION_FUERA_DE_RANGO = "Opción fuera de rango"
ANCHO_NUMERO = 6
ANCHO_TEXTO = 30

#  Credenciales sensibles .env
API_KEY = os.getenv("API_KEY")
DB_HOST = os.getenv("DB_HOST")
DB_PASS = os.getenv("DB_PASS")


#  Roles del sistema
ROL_ADMIN    = "admin"
ROL_ANALISTA = "analista"
ROL_EMPLEADO = "empleado"
ROLES_VALIDOS=[ROL_ADMIN, ROL_ANALISTA, ROL_EMPLEADO] #* Se creo para verificar que se ingreso un rol valido en el registro

#  FUNCIONES DE UTILIDAD

def buscar_empleado(id):
    for e in empleados:
        if e["id"] == id:
            return e
    return None

def buscar_departamento(id):
    for d in departamentos:
        if d["id"] == id:
            return d
    return None

def buscar_usuario(username):
    for u in usuarios_rrhh:
        if u["username"] == username:
            return u
    return None

def pedir_dato_valido(pregunta, condicion, mensaje_error):    #! Funcion creada para pedir inputs correctamente y validos
    while True:
        valor = input(pregunta)
        if condicion(valor):
            return valor
        else:
            print(mensaje_error)

#! Funciones para verificar un rut valido
def calcular_dv(rut_sin_dv):
    suma = 0
    factor = 2

    for digito in reversed(rut_sin_dv):
        suma += int(digito) * factor
        factor += 1
        if factor > 7:
            factor = 2

    resto = suma % 11
    resultado = 11 - resto

    if resultado == 11:
        return "0"
    elif resultado == 10:
        return "K"
    else:
        return str(resultado)

def validar_rut(rut_completo):
    limpio = rut_completo.replace(" ", "").replace("-", "").replace(".", "").upper()
    dv_calculado = calcular_dv(limpio[:-1])
    return dv_calculado == limpio[-1]


#  MENÚS
def menu_principal(rol):
    print(SEPARADOR)
    print("   S I S T E M A   R R H H     ")
    print(SEPARADOR)
    print("       1.- EMPLEADOS            ")
    print("       2.- DEPARTAMENTOS        ")
    print("       3.- LIQUIDACIÓN          ")

    if rol == ROL_ADMIN or rol == ROL_ANALISTA:
        print("       4.- CARGAR CONFIG YAML   ")
        print("       5.- REPORTES             ")
        print("       6.- Salir                ")
    else:
        print("       4.- Salir                ")
    print(SEPARADOR)
    print(f"  [INFO] Sesión iniciada")

def menu_empleados():
    print(SEPARADOR)
    print("   G E S T I Ó N  E M P L E A D O S")
    print(SEPARADOR)
    print("       1.- AGREGAR EMPLEADO     ")
    print("       2.- MOSTRAR TODOS        ")
    print("       3.- MOSTRAR UNO          ")
    print("       4.- MODIFICAR EMPLEADO   ")
    print("       5.- ELIMINAR EMPLEADO    ")
    print("       6.- VOLVER               ")
    print(SEPARADOR)

def menu_departamentos():
    print(SEPARADOR)
    print("   G E S T I Ó N  D E P T O S  ")
    print(SEPARADOR)
    print("       1.- AGREGAR DEPTO        ")
    print("       2.- MOSTRAR TODOS        ")
    print("       3.- ELIMINAR DEPTO       ")
    print("       4.- VOLVER               ")
    print(SEPARADOR)

#  USUARIOS
def registrar_usuario_rrhh():
    print(SEPARADOR)
    print("      REGISTRO DE USUARIO RRHH         ")
    print(SEPARADOR)
    username = input("INGRESE NOMBRE DE USUARIO: ")

    #!Verificacion de datos ingresados clave|nombre|rol
    clave = pedir_dato_valido(
        "INGRESE CONTRASEÑA       : ",
        lambda c: len(c) >= 8 and any(x.isupper() for x in c) and any(x.islower() for x in c) and any(x.isdigit() for x in c),
        "La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un número."
    )

    nombre = pedir_dato_valido(
        "INGRESE NOMBRE: ",
        lambda n: not any(x.isdigit() for x in n),
        "Un nombre no puede contener numeros."
    )

    rol = pedir_dato_valido(
        "INGRESE ROL (admin/analista/empleado): ",
        lambda r: r in ROLES_VALIDOS,
        "Ingrese un rol valido."
    )

    id_emp_vinculado = None

    if rol == ROL_EMPLEADO:
        rut_vinculo = pedir_dato_valido(
            "INGRESE SU RUT (para vincular con su ficha de empleado): ",
            validar_rut,
            "RUT invalido, vuelva a intentarlo."
        )

        rut_normalizado = rut_vinculo.replace(" ", "").replace("-", "").replace(".", "").upper()

        emp_encontrado = None
        for emp in empleados:
            emp_rut_normalizado = emp["rut"].replace(" ", "").replace("-", "").replace(".", "").upper()
            if emp_rut_normalizado == rut_normalizado:
                emp_encontrado = emp
                break

        if emp_encontrado is None:
            print("No existe una ficha de empleado con ese RUT. Contacte a RRHH.")
            input(MSG_PRESIONE_ENTER)
            return

        id_emp_vinculado = emp_encontrado["id"]

    global id_usuario
    id_usuario += 1

    hash_clave = bcrypt.hashpw(clave.encode(), bcrypt.gensalt()) #!bcrypt 

    usuario = {
        "id"       : id_usuario,
        "username" : username,
        "clave"    : hash_clave,
        "nombre"   : nombre,
        "rol"      : rol,
        "id_empleado" : id_emp_vinculado
        }
    usuarios_rrhh.append(usuario)
    print("Usuario RRHH registrado correctamente.")

def iniciar_sesion():
    print(SEPARADOR)
    print("      INICIO DE SESIÓN      ")
    print(SEPARADOR)
    user  = input("Ingrese nombre de usuario: ")
    clave = input("Ingrese contraseña       : ")

    #! Se agrego un try|except por si llega a fallar bcrypt
    usuario = buscar_usuario(user)
    if usuario:
        try:
            if bcrypt.checkpw(clave.encode(), usuario["clave"]):
                print(f"Bienvenido {usuario['nombre']}.")
                return usuario
            else:
                print("Contraseña incorrecta.")
        except Exception as e:
            print(f"Error inesperado: {e}")
    else:
        print("Usuario no registrado.")
    return None


#  DEPARTAMENTOS
def agregar_departamento(rol):
    #! Se agrego verificacion, solo admin puede crear un dep
    if rol != ROL_ADMIN:
        print(SEPARADOR)
        print("Acceso Denedago.")
        print(SEPARADOR)
        input(MSG_PRESIONE_ENTER)
        return
    
    print(SEPARADOR)
    print("      AGREGAR DEPARTAMENTO       ")
    print(SEPARADOR)
    
    nombre = pedir_dato_valido(
        "INGRESE NOMBRE DEL DEPARTAMENTO: ",
        lambda n: not any(x.isdigit() for x in n),
        "El nombre del departamento no puede contener numeros."
    )
    
    jefe = pedir_dato_valido(
        "INGRESE NOMBRE DEL JEFE        : ",
        lambda j: not any(x.isdigit() for x in j),
        "El nombre del jefe no puede contener numeros."
    )
    
    presupuesto = input("INGRESE PRESUPUESTO MENSUAL    : ")
    
    global id_dpto
    id_dpto += 1
    
    try:
        dpto = {
            "id"          : id_dpto,
            "nombre"      : nombre,
            "jefe"        : jefe,
            "presupuesto" : float(presupuesto),
            "empleados"   : 0
        }
        departamentos.append(dpto)
        print("Departamento agregado correctamente.")
    except ValueError:
        print("El presupuesto debe ser un numero valido.")
        input(MSG_PRESIONE_ENTER)
        id_dpto -= 1

def mostrar_departamentos():
    print(SEPARADOR)
    print("     LISTADO DE DEPARTAMENTOS    ")
    print(SEPARADOR)
    if len(departamentos) == 0:
        print("No hay departamentos registrados.")
        return
    for d in departamentos:
        print(" ID: {} | NOMBRE: {} | JEFE: {} | PRESUPUESTO: ${} | EMPLEADOS: {}".format(
            d["id"], d["nombre"], d["jefe"], d["presupuesto"], d["empleados"]))
        print(SEPARADOR * 2)

def eliminar_departamento(rol):
    #! Solo admin puede eliminar un dep
    if rol != ROL_ADMIN:
        print(SEPARADOR)
        print("Acceso Denedago.")
        print(SEPARADOR)
        input(MSG_PRESIONE_ENTER)
        return
    
    print(SEPARADOR)
    print("      ELIMINAR DEPARTAMENTO      ")
    print(SEPARADOR)
    mostrar_departamentos()
    #! Se agrego try por id no numerico
    try:
        elim = int(input("Ingrese ID del departamento a eliminar: "))
        d    = buscar_departamento(elim)
        if d:
            departamentos.remove(d)
            print("Departamento eliminado.")
        else:
            print("Departamento no encontrado.")
    except ValueError:
        print("El ID debe ser numerico.")
        input(MSG_PRESIONE_ENTER)

#  EMPLEADOS
def agregar_empleado(rol):
    if rol == ROL_EMPLEADO:
        print(SEPARADOR)
        print("Acceso Denedago.")
        print(SEPARADOR)
        input(MSG_PRESIONE_ENTER)
        return
    
    print(SEPARADOR)
    print("       AGREGAR NUEVO EMPLEADO    ")
    print(SEPARADOR)

    rut = pedir_dato_valido(
        "INGRESE RUT        : ",
        validar_rut,
        "RUT invalido, vuelva a intentarlo."
    )

    nombre = pedir_dato_valido(
        "INGRESE NOMBRE     : ",
        lambda n: not any(x.isdigit() for x in n),
        "Un nombre no puede contener numeros."
    ).capitalize()

    apellido = pedir_dato_valido(
        "INGRESE APELLIDO   : ",
        lambda n: not any(x.isdigit() for x in n),
        "Un apellido no puede contener numeros."
    ).capitalize()
    
    correo = pedir_dato_valido(
    "INGRESE CORREO     : ",
    lambda co: co.count("@") == 1 and len(co.split("@")[0]) > 0 and len(co.split("@")[1]) > 0 and "." in co.split("@")[1],
    "Correo invalido, verifique el formato (nombre@dominio.com)."
    ).lower()

    fono = pedir_dato_valido(
        "INGRESE TELEFONO   : ",
        lambda f: len(f)==9 and all(x.isdigit() for x in f),
        "Ingrese un telefono valido '912345678'"
    )

    sueldo_base = pedir_dato_valido(
        "INGRESE SUELDO BASE: ",
        lambda s: s.replace(".", "", 1).isdigit() and s.count(".") <= 1,
        "Ingrese un sueldo valido."
    )

    cargo = pedir_dato_valido(
        "INGRESE CARGO      : ",
        lambda c: not any(x.isdigit() for x in c),
        "El cargo no puede contener numeros."
    ).capitalize()

    if len(departamentos) == 0:
        print(SEPARADOR)
        print("No hay departamentos registrados. Debe crear uno primero.")
        print(SEPARADOR)
        input(MSG_PRESIONE_ENTER)
        return

    mostrar_departamentos()

    id_d = pedir_dato_valido(
        "INGRESE ID DEL DEPARTAMENTO: ",
        lambda i: i.isdigit() and buscar_departamento(int(i)) is not None,
        "Ingrese un ID valido."
    )


    global id_empleado
    id_empleado += 1

    codigo = "EMP-" + str(secrets.token_hex(4)) #! Genera codigos randoms seguros

    empleado = {
        "id"          : id_empleado,
        "codigo"      : codigo,
        "rut"         : rut,
        "nombre"      : nombre,
        "apellido"    : apellido,
        "correo"      : correo,
        "fono"        : fono,
        "sueldo_base" : float(sueldo_base),
        "cargo"       : cargo,
        "id_dpto"     : int(id_d),
        "estado"      : "ACTIVO"
    }
    empleados.append(empleado)

    d = buscar_departamento(int(id_d))
    if d:
        d["empleados"] += 1

    print("Empleado agregado. Código: {}".format(codigo))

def mostrar_empleados():
    print(SEPARADOR)
    print("      LISTADO DE EMPLEADOS       ")
    print(SEPARADOR)
    if len(empleados) == 0:
        print("No hay empleados registrados.")
        return
    for e in empleados:
        print(" ID: {} | COD: {} | RUT: {} | NOMBRE: {} {} | CARGO: {} | SUELDO: ${} | ESTADO: {}".format(
            e["id"], e["codigo"], e["rut"], e["nombre"], e["apellido"],
            e["cargo"], e["sueldo_base"], e["estado"]))
        print("-" * 100)

def mostrar_empleado_uno():
    print(SEPARADOR)
    print("    MOSTRAR EMPLEADO POR ID      ")
    print(SEPARADOR)

    try:
        id_buscar = int(input("Ingrese el ID del empleado: "))

    except ValueError:
        print("ID invalido. Debe ingresar un numero.")
        input(MSG_PRESIONE_ENTER)
        return
    
    e = buscar_empleado(id_buscar)
    if e:
        print(" ID          : {}".format(e["id"]))
        print(" CÓDIGO      : {}".format(e["codigo"]))
        print(" RUT         : {}".format(e["rut"]))
        print(" NOMBRE      : {} {}".format(e["nombre"], e["apellido"]))
        print(" CORREO      : {}".format(e["correo"]))
        print(" TELÉFONO    : {}".format(e["fono"]))
        print(" SUELDO BASE : ${}".format(e["sueldo_base"]))
        print(" CARGO       : {}".format(e["cargo"]))
        print(" DEPARTAMENTO: {}".format(e["id_dpto"]))
        print(" ESTADO      : {}".format(e["estado"]))
    else:
        print(MSG_EMPLEADO_NO_ENCONTRADO)
    input(MSG_PRESIONE_ENTER)

def modificar_empleado(rol):
    if rol == ROL_EMPLEADO:
        print(SEPARADOR)
        print("Acceso Denedago.")
        print(SEPARADOR)
        input(MSG_PRESIONE_ENTER)
        return
    
    print(SEPARADOR)
    print("       MODIFICAR EMPLEADO          ")
    print(SEPARADOR)
    mostrar_empleados()

    try:
        mod = int(input("\nIngrese ID del empleado a modificar: "))
    
    except ValueError:
        print("ID debe ser numerico.")
        input(MSG_PRESIONE_ENTER)
        return
    
    e = buscar_empleado(mod)
    if not e:
        print(MSG_EMPLEADO_NO_ENCONTRADO)
        input(MSG_PRESIONE_ENTER)
        return

    opm = input("DESEA MODIFICAR EL NOMBRE: {} - [SI/NO] ".format(e["nombre"]))
    if opm.lower() == "si":
        e["nombre"] = input("INGRESE NUEVO NOMBRE: ")

    opm = input("DESEA MODIFICAR EL APELLIDO: {} - [SI/NO] ".format(e["apellido"]))
    if opm.lower() == "si":
        e["apellido"] = input("INGRESE NUEVO APELLIDO: ")

    opm = input("DESEA MODIFICAR EL CORREO: {} - [SI/NO] ".format(e["correo"]))
    if opm.lower() == "si":
        e["correo"] = input("INGRESE NUEVO CORREO: ")

    opm = input("DESEA MODIFICAR EL SUELDO BASE: {} - [SI/NO] ".format(e["sueldo_base"]))
    if opm.lower() == "si":
        try:
            e["sueldo_base"] = float(input("INGRESE NUEVO SUELDO: "))
        except ValueError:
            print("Sueldo invalido. No se modifico el sueldo.")

    print("Empleado modificado correctamente.")
    input(MSG_PRESIONE_ENTER)

def eliminar_empleado(rol):
    if rol != ROL_ADMIN:
        print(SEPARADOR)
        print("Acceso Denedago.")
        print(SEPARADOR)
        input(MSG_PRESIONE_ENTER)
        return
    
    print(SEPARADOR)
    print("        ELIMINAR EMPLEADO          ")
    print(SEPARADOR)
    mostrar_empleados()
    try:
        elim = int(input("Ingrese ID del empleado a eliminar: "))

    except ValueError:
        print("ID debe ser numerico.")
        input(MSG_PRESIONE_ENTER)
        return
    
    e = buscar_empleado(elim)
    if e:
        empleados.remove(e)
        print("Empleado eliminado.")
    else:
        print(MSG_EMPLEADO_NO_ENCONTRADO)


#  ANONIMIZACIÓN
def anonimizar_rut(rut):
    limpio = rut.replace(" ", "").replace("-", "").replace(".", "").upper()
    return "****" + limpio[-4:]  # Sin anonimizar — expone dato sensible

def anonimizar_sueldo(sueldo):
    piso  = int(sueldo // 100000) * 100000
    techo = piso + 100000
    return "Entre ${:,.0f} y ${:,.0f}".format(piso, techo).replace(",", ".")

def reporte_empleados_anonimizado():
    print(SEPARADOR)
    print("  REPORTE EMPLEADOS (ANONIMIZADO)")
    print(SEPARADOR)

    if len(empleados) == 0:
        print("No hay empleados registrados.")
        input(MSG_PRESIONE_ENTER)
        return

    for e in empleados:
        rut_vis    = anonimizar_rut(e["rut"])
        sueldo_vis = anonimizar_sueldo(e["sueldo_base"])
        print(" COD: {} | RUT: {} | NOMBRE: {} {} | CARGO: {} | SUELDO: {}".format(
            e["codigo"], rut_vis, e["nombre"], e["apellido"], e["cargo"], sueldo_vis))
    input(MSG_PRESIONE_ENTER)


#  LIQUIDACIÓN
def calcular_liquidacion(usuario_actual):
    print(SEPARADOR)
    print("    CÁLCULO DE LIQUIDACIÓN       ")
    print(SEPARADOR)

    rol = usuario_actual["rol"]

    if rol == ROL_EMPLEADO:
        id_e = usuario_actual["id_empleado"]
        if id_e is None:
            print("Su usuario no tiene un empleado vinculado. Contacte a RRHH.")
            input(MSG_PRESIONE_ENTER)
            return
        e = buscar_empleado(id_e)
    else:
        mostrar_empleados()

        try:
            id_e = int(input("Ingrese ID del empleado: "))

        except ValueError:
            print("ID debe ser numerico.")
            input(MSG_PRESIONE_ENTER)
            return
        
        e = buscar_empleado(id_e)

    if not e:
        print(MSG_EMPLEADO_NO_ENCONTRADO)
        input(MSG_PRESIONE_ENTER)
        return

    try:
        horas_extra = int(input("Ingrese horas extra trabajadas: "))
    except ValueError:
        print("Las horas extra deben ser numericas.")
        input(MSG_PRESIONE_ENTER)
        return

    DESCUENTO_SALUD   = 0.07
    DESCUENTO_AFP     = 0.10
    HORAS_MES         = 180
    FACTOR_HORA_EXTRA = 1.5

    sueldo     = e["sueldo_base"]
    desc_salud = sueldo * DESCUENTO_SALUD
    desc_afp   = sueldo * DESCUENTO_AFP
    bono_extra = (sueldo / HORAS_MES) * horas_extra * FACTOR_HORA_EXTRA
    sueldo_liq = sueldo - desc_salud - desc_afp + bono_extra

    print(SEPARADOR)
    print("       LIQUIDACIÓN DE SUELDO    ")
    print(SEPARADOR)
    print(" Empleado    : {} {}".format(e["nombre"], e["apellido"]))
    print(" Sueldo Base : ${}".format(sueldo))
    print(" Desc. Salud : ${}".format(desc_salud))
    print(" Desc. AFP   : ${}".format(desc_afp))
    print(" Bono Extra  : ${}".format(bono_extra))
    print(" SUELDO LÍQ. : ${}".format(sueldo_liq))
    print(SEPARADOR)
    input(MSG_PRESIONE_ENTER)


#  CONFIGURACIÓN YAML
def cargar_config_yaml(rol):
    if rol != ROL_ADMIN:
        print(SEPARADOR)
        print("Acceso Denedago.")
        print(SEPARADOR)
        input(MSG_PRESIONE_ENTER)
        return
    
    print("Cargando configuración del sistema...")
    ruta = input("Ingrese ruta del archivo de configuración YAML: ")

    try:
        with open(ruta, "r") as f:
            config = yaml.safe_load(f)  #* Evita el codigo arbitrario
    except FileNotFoundError:
        print("El archivo no existe. Verifique la ruta.")
        input(MSG_PRESIONE_ENTER)
        return
    except yaml.YAMLError:
        print("El archivo no tiene un formato YAML valido.")
        input(MSG_PRESIONE_ENTER)
        return
    
    print("Configuración cargada: {}".format(config))
    input(MSG_PRESIONE_ENTER)
    return config

#  REPORTES
def generar_informe(rol):
    if rol == ROL_EMPLEADO:
        print(SEPARADOR)
        print("Acceso Denedago.")
        print(SEPARADOR)
        input(MSG_PRESIONE_ENTER)
        return

    print(SEPARADOR)
    print("       GENERAR INFORME           ")
    print(SEPARADOR)
    tipo   = input("Ingrese tipo de informe (pdf/excel/txt): ")
    nombre = input("Ingrese nombre del archivo            : ")

    #! subprocess.run evita el command injection pe
    subprocess.run(["echo", "Informe", tipo, nombre], shell=False)
    print("Informe generado.")
    input(MSG_PRESIONE_ENTER)

def menu_reportes():
    print(SEPARADOR)
    print("     M E N Ú  R E P O R T E S  ")
    print(SEPARADOR)
    print("       1.- GENERAR INFORME      ")
    print("       2.- NÓMINA ANONIMIZADA   ")
    print("       3.- VOLVER               ")
    print(SEPARADOR)


#  GESTIÓN POR MÓDULOS
def gestion_departamentos(rol):
    while True:
        menu_departamentos()
        try:
            op = int(input(MSG_INGRESE_OPCION))
        except ValueError:
            print(MSG_OPCION_FUERA_DE_RANGO)
            continue

        if op == 1:
            agregar_departamento(rol)
        elif op == 2:
            mostrar_departamentos()
            input(MSG_PRESIONE_ENTER)
        elif op == 3:
            eliminar_departamento(rol)
        elif op == 4:
            break
        else:
            print(MSG_OPCION_FUERA_DE_RANGO)

def gestion_empleados(rol):
    while True:
        menu_empleados()
        try:
            op = int(input(MSG_INGRESE_OPCION))
        except ValueError:
            print(MSG_OPCION_FUERA_DE_RANGO)
            continue

        if op == 1:
            agregar_empleado(rol)
        elif op == 2:
            mostrar_empleados()
            input(MSG_PRESIONE_ENTER)
        elif op == 3:
            mostrar_empleado_uno()
        elif op == 4:
            modificar_empleado(rol)
        elif op == 5:
            eliminar_empleado(rol)
        elif op == 6:
            break
        else:
            print(MSG_OPCION_FUERA_DE_RANGO)

def gestion_reportes(rol):
    while True:
        menu_reportes()
        try:
            op = int(input(MSG_INGRESE_OPCION))
        except ValueError:
            print(MSG_OPCION_FUERA_DE_RANGO)
            continue

        if op == 1:
            generar_informe(rol)
        elif op == 2:
            reporte_empleados_anonimizado()
        elif op == 3:
            break
        else:
            print(MSG_OPCION_FUERA_DE_RANGO)


#  FLUJO PRINCIPAL
def menu_auth():
    print(SEPARADOR)
    print("   M E N Ú  A C C E S O        ")
    print(SEPARADOR)
    print("       1.- INICIAR SESIÓN       ")
    print("       2.- REGISTRAR USUARIO    ")
    print("       3.- Salir                ")
    print(SEPARADOR)

while True:
    menu_auth()
    try:
        opAuth = int(input(MSG_INGRESE_OPCION))
    except ValueError:
        print(MSG_OPCION_FUERA_DE_RANGO)
        continue

    if opAuth == 1:
        usuario_actual = iniciar_sesion()
        if usuario_actual:
            rol_actual = usuario_actual["rol"]
            input("Presiona ENTER para ingresar al Sistema RRHH.")
            while True:
                menu_principal(rol_actual)
                try:
                    op = int(input(MSG_INGRESE_OPCION))
                except ValueError:
                    print(MSG_OPCION_FUERA_DE_RANGO)
                    continue

                if rol_actual == ROL_ADMIN or rol_actual == ROL_ANALISTA:
                    if op == 1:
                        gestion_empleados(rol_actual)
                    elif op == 2:
                        gestion_departamentos(rol_actual)
                    elif op == 3:
                        calcular_liquidacion(usuario_actual)
                    elif op == 4:
                        cargar_config_yaml(rol_actual)
                    elif op == 5:
                        gestion_reportes(rol_actual)
                    elif op == 6:
                        op_salir = input("¿DESEA SALIR [SI/NO]: ")
                        if op_salir.lower() == "si":
                            break
                    else:
                        print(MSG_OPCION_FUERA_DE_RANGO)
                else:
                    if op == 1:
                        gestion_empleados(rol_actual)
                    elif op == 2:
                        gestion_departamentos(rol_actual)
                    elif op == 3:
                        calcular_liquidacion(usuario_actual)
                    elif op == 4:
                        op_salir = input("¿DESEA SALIR [SI/NO]: ")
                        if op_salir.lower() == "si":
                            break
                    else:
                        print(MSG_OPCION_FUERA_DE_RANGO)
            break
    elif opAuth == 2:
        registrar_usuario_rrhh()
    elif opAuth == 3:
        op_salir = input("¿DESEA SALIR [SI/NO]: ")
        if op_salir.lower() == "si":
            break
    else:
        print(MSG_OPCION_FUERA_DE_RANGO)