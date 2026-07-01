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

import hashlib #* Hasheo
import os      #* Sistema 
import random  #* Random
import yaml    #* Orden¿
import subprocess #* para el subprocess.run
from dotenv import load_dotenv

load_dotenv() #* Conecta el .py con el .env

#  Variables|Listas importantes
empleados     = []
departamentos = []
usuarios_rrhh = []
id_empleado   = 0
id_dpto       = 0
id_usuario    = 0

#  Variables printeables
SEPARADOR = "="*40
MSG_EMPLEADO_NO_ENCONTRADO = "Empleado no encontrado."
MSG_PRESIONE_ENTER = "\n\nPRESIONE ENTER PARA CONTINUAR"
MSG_INGRESE_OPCION = "INGRESE OPCIÓN: "
MSG_OPCION_FUERA_DE_RANGO = "Opción fuera de rango"

#  Credenciales sensibles .env
API_KEY = os.getenv("API_KEY")
DB_HOST = os.getenv("DB_HOST")
DB_PASS = os.getenv("DB_PASS")


#  Roles del sistema
ROL_ADMIN    = "admin"
ROL_ANALISTA = "analista"
ROL_EMPLEADO = "empleado"


#  FUNCIONES DE BÚSQUEDA
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


#  MENÚS
def menu_principal(rol):
    print(SEPARADOR)
    print("   S I S T E M A   R R H H     ")
    print(SEPARADOR)
    print("       1.- EMPLEADOS            ")
    print("       2.- DEPARTAMENTOS        ")
    print("       3.- LIQUIDACIÓN          ")
    # [CONTROL DE ACCESO] Las opciones 4 y 5 son sensibles pero se muestran #*k xuxa
    # a todos los roles incluyendo ROL_EMPLEADO
    if rol:
        pass #! A tomar por culo
    print("       4.- CARGAR CONFIG YAML   ")
    print("       5.- REPORTES             ")
    print("       6.- Salir                ")
    print(SEPARADOR)
    if rol == ROL_EMPLEADO:
        print("  [INFO] Sesión como EMPLEADO")

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
    clave    = input("INGRESE CONTRASEÑA       : ") #! Posible while True e if para verificar complejidad

    # [INTEGRIDAD - VALIDACIÓN] No se valida complejidad de contraseña
    # Corrección esperada (las CUATRO condiciones deben cumplirse):
    #   1. len(clave) >= 8
    #   2. any(c.isupper() for c in clave)  → al menos una mayúscula
    #   3. any(c.islower() for c in clave)  → al menos una minúscula
    #   4. any(c.isdigit() for c in clave)  → al menos un dígito

    nombre = input("INGRESE NOMBRE: ")
    rol    = input("INGRESE ROL (admin/analista/empleado): ")

    global id_usuario
    id_usuario += 1

    # [CONFIDENCIALIDAD - B324] MD5 sin salt — vulnerable a rainbow tables
    # Corrección: bcrypt o hashlib.sha256 con salt aleatorio
    hash_clave = hashlib.md5(clave.encode()).hexdigest() #! Linea 130 (Bandit) hasheo penka

    usuario = {
        "id"       : id_usuario,
        "username" : username,
        "clave"    : hash_clave,
        "nombre"   : nombre,
        "rol"      : rol
    }
    usuarios_rrhh.append(usuario)
    print("Usuario RRHH registrado correctamente.")

def iniciar_sesion():
    print(SEPARADOR)
    print("           INICIO DE SESIÓN            ")
    print(SEPARADOR)
    user  = input("Ingrese nombre de usuario: ")
    clave = input("Ingrese contraseña       : ")

    # [DISPONIBILIDAD] Sin try/except: un fallo inesperado tumba el sistema #! Agregar try/except para k no tumbe
    usuario = buscar_usuario(user)
    if usuario:
        hash_ingresada = hashlib.md5(clave.encode()).hexdigest() #! Linea 152 (Bandit) Hasheo penka
        if usuario["clave"] == hash_ingresada:
            # [CONFIDENCIALIDAD] Imprime el hash de la contraseña en pantalla
            print(f"Bienvenido {usuario['nombre']} - Perfil: {usuario['rol']} - hash: {usuario['clave']}.")
            return usuario
        else:
            print("Contraseña incorrecta.")
    else:
        print("Usuario no registrado.")
    return None


#  DEPARTAMENTOS
def agregar_departamento(rol):
    # [CONTROL DE ACCESO] Cualquier rol puede agregar departamentos #! Agregar validacion, agregar dep solo admin
    # Corrección: if rol != ROL_ADMIN: print("Acceso denegado"); return
    print(SEPARADOR)
    print("      AGREGAR DEPARTAMENTO       ")
    print(SEPARADOR)
    nombre      = input("INGRESE NOMBRE DEL DEPARTAMENTO: ")
    jefe        = input("INGRESE NOMBRE DEL JEFE        : ")
    presupuesto = input("INGRESE PRESUPUESTO MENSUAL    : ")

    global id_dpto
    id_dpto += 1

    # [DISPONIBILIDAD] Sin try/except: crash si presupuesto no es numérico #! agregar try/except por presupuesto no numerico
    dpto = {
        "id"          : id_dpto,
        "nombre"      : nombre,
        "jefe"        : jefe,
        "presupuesto" : float(presupuesto),
        "empleados"   : 0
    }
    departamentos.append(dpto)
    print("Departamento agregado correctamente.")

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
        print("-" * 75)

def eliminar_departamento(rol):
    # [CONTROL DE ACCESO] Cualquier rol puede eliminar departamentos #! Agregar validacion, eliminar dep solo admin
    # Corrección: if rol != ROL_ADMIN: print("Acceso denegado"); return
    print(SEPARADOR)
    print("      ELIMINAR DEPARTAMENTO      ")
    print(SEPARADOR)
    mostrar_departamentos()
    elim = int(input("Ingrese ID del departamento a eliminar: "))
    d    = buscar_departamento(elim)
    if d:
        departamentos.remove(d)
        print("Departamento eliminado.")
    else:
        print("Departamento no encontrado.")


#  EMPLEADOS
def agregar_empleado(rol):
    # [CONTROL DE ACCESO] Un empleado no debería poder agregar otros empleados #! Agregar validacion,
    # Corrección: if rol == ROL_EMPLEADO: print("Acceso denegado"); return     #! un empleado no puede agrear a otro 
    print(SEPARADOR)
    print("       AGREGAR NUEVO EMPLEADO    ")
    print(SEPARADOR)
    rut         = input("INGRESE RUT     : ")
    nombre      = input("INGRESE NOMBRE  : ")
    apellido    = input("INGRESE APELLIDO: ") #! Pedir bien los inputs (try/except)
    correo      = input("INGRESE CORREO  : ")
    fono        = input("INGRESE TELÉFONO: ")
    sueldo_base = input("INGRESE SUELDO BASE: ")
    cargo       = input("INGRESE CARGO   : ")
    mostrar_departamentos()
    id_d        = input("INGRESE ID DEL DEPARTAMENTO: ")

    global id_empleado
    id_empleado += 1

    # [INTEGRIDAD - S2245] random.randint no es seguro para generar códigos únicos
    # Corrección: secrets.token_hex(4) o uuid.uuid4()
    codigo = "EMP-" + str(random.randint(100, 999)) #! Linea 243 (Bandit), codigos penka

    # [DISPONIBILIDAD] Sin try/except: crash si sueldo_base o id_d no son numéricos #! comentario de la 230
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

    d = buscar_departamento(int(id_d)) #! ta rara la wea (revisar)
    if d:
        d["empleados"] += 1

    print("Empleado agregado. Código: {}".format(codigo))

def mostrar_empleados():
    print(SEPARADOR)
    print("      LISTADO DE EMPLEADOS       ")
    print(SEPARADOR)
    if len(empleados) == 0:
        print("No hay empleados registrados.")
        return #! k leches con ese return solito
    for e in empleados:
        print(" ID: {} | COD: {} | RUT: {} | NOMBRE: {} {} | CARGO: {} | SUELDO: ${} | ESTADO: {}".format(
            e["id"], e["codigo"], e["rut"], e["nombre"], e["apellido"],
            e["cargo"], e["sueldo_base"], e["estado"]))
        print("-" * 100)

def mostrar_empleado_uno():
    print(SEPARADOR)
    print("    MOSTRAR EMPLEADO POR ID      ")
    print(SEPARADOR)
    # [DISPONIBILIDAD] Sin try/except sobre int() #! Agregar el try/except para k no tumbe la mrd al no colocar numero id_buscar
    id_buscar = int(input("Ingrese el ID del empleado: "))
    e         = buscar_empleado(id_buscar)
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
    # [CONTROL DE ACCESO] Un empleado no debería modificar a otros empleados #! un empleado qlio no puede modificar otro aweonao
    # Corrección: if rol == ROL_EMPLEADO: print("Acceso denegado"); return
    print(SEPARADOR)
    print("       MODIFICAR EMPLEADO          ")
    print(SEPARADOR)
    mostrar_empleados()
    # [DISPONIBILIDAD] Sin try/except sobre int() #! un try 
    mod = int(input("\nIngrese ID del empleado a modificar: "))
    e   = buscar_empleado(mod)
    if not e:
        print(MSG_EMPLEADO_NO_ENCONTRADO)
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
        e["sueldo_base"] = float(input("INGRESE NUEVO SUELDO: "))

    print("Empleado modificado correctamente.")

def eliminar_empleado(rol):
    # [CONTROL DE ACCESO] Solo admin debería eliminar empleados #! Solo admin puede eliminar empleados pe
    # Corrección: if rol != ROL_ADMIN: print("Acceso denegado"); return
    print(SEPARADOR)
    print("        ELIMINAR EMPLEADO          ")
    print(SEPARADOR)
    mostrar_empleados()
    elim = int(input("Ingrese ID del empleado a eliminar: "))
    e    = buscar_empleado(elim)
    if e:
        empleados.remove(e)
        print("Empleado eliminado.")
    else:
        print(MSG_EMPLEADO_NO_ENCONTRADO)


#  ANONIMIZACIÓN    #!Aprender que mierda es anonimizacion y anonimizar toda la fakin mrd
def anonimizar_rut(rut):
    """
    [CONFIDENCIALIDAD - ANONIMIZACIÓN]
    Debe enmascarar el RUT para reportes externos o de auditoría.
    ERROR: Retorna el RUT completo, exponiendo dato personal sensible.
    Corrección: return "****" + rut[-4:]
    Ejemplo correcto: "12.345.678-9" → "****678-9"
    """
    return rut  # Sin anonimizar — expone dato sensible

def anonimizar_sueldo(sueldo):
    """
    [CONFIDENCIALIDAD - ANONIMIZACIÓN / SEUDONIMIZACIÓN]
    Los sueldos son datos sensibles que deben anonimizarse en reportes públicos.
    ERROR: Retorna el sueldo exacto.
    Corrección: retornar rango salarial
    Ejemplo correcto: 850000 → "Entre $800.000 y $900.000"
    """
    return sueldo  # Sin anonimizar — expone sueldo exacto

def reporte_empleados_anonimizado():
    print(SEPARADOR)
    print("  REPORTE EMPLEADOS (ANONIMIZADO)")
    print(SEPARADOR)
    for e in empleados:
        rut_vis    = anonimizar_rut(e["rut"])
        sueldo_vis = anonimizar_sueldo(e["sueldo_base"])
        print(" COD: {} | RUT: {} | NOMBRE: {} {} | CARGO: {} | SUELDO: ${}".format(
            e["codigo"], rut_vis, e["nombre"], e["apellido"], e["cargo"], sueldo_vis))
    input(MSG_PRESIONE_ENTER)


#  LIQUIDACIÓN
def calcular_liquidacion(rol): #! Linea 388 (sonar) no se ocupa la mrd de rol
    # [CONTROL DE ACCESO] Un empleado solo debería ver su propia liquidación #! lee mrd
    # Corrección: filtrar por el empleado vinculado al usuario en sesión
    print(SEPARADOR)
    print("    CÁLCULO DE LIQUIDACIÓN       ")
    print(SEPARADOR)
    mostrar_empleados()
    # [DISPONIBILIDAD] Sin try/except sobre int() #! Agregar Try mrd
    id_e     = int(input("Ingrese ID del empleado: "))
    e        = buscar_empleado(id_e)
    if not e:
        print(MSG_EMPLEADO_NO_ENCONTRADO)
        return

    horas_extra = int(input("Ingrese horas extra trabajadas: "))

    # [INTEGRIDAD - S109] Números mágicos sin constantes nombradas 
    # Corrección: DESCUENTO_SALUD = 0.07 / DESCUENTO_AFP = 0.10 / HORAS_MES = 180 #! conchatumare
    sueldo     = e["sueldo_base"]
    desc_salud = sueldo * 0.07
    desc_afp   = sueldo * 0.10
    bono_extra = (sueldo / 180) * horas_extra * 1.5
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
def cargar_config_yaml(rol): #! creo k a la xuxa ese rol k no se ocupa xd (actualizacion si se ocupa, lee mrd)
    # [CONTROL DE ACCESO] Solo el admin debería cargar configuraciones del sistema #! ve esa webada
    # Corrección: if rol != ROL_ADMIN: print("Acceso denegado"); return
    print("Cargando configuración del sistema...")
    ruta = input("Ingrese ruta del archivo de configuración YAML: ")

    # [DISPONIBILIDAD] Sin try/except: si el archivo no existe → crash
    with open(ruta, "r") as f:
        config = yaml.safe_load(f) #* Evita el codigo arbitrario
    print("Configuración cargada: {}".format(config))
    return config


#  REPORTES
def generar_informe(rol):
    # [CONTROL DE ACCESO] Empleados no deberían generar informes con datos de la nómina #! empleados qlios no pueden
    # Corrección: if rol == ROL_EMPLEADO: print("Acceso denegado"); return              #! agregar informes de la nomina
    print(SEPARADOR)
    print("       GENERAR INFORME           ")
    print(SEPARADOR)
    tipo   = input("Ingrese tipo de informe (pdf/excel/txt): ")
    nombre = input("Ingrese nombre del archivo            : ")

    # subprocess.run evita el command injection
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
        op = int(input(MSG_INGRESE_OPCION))
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
                                            #! constante pork se ocupa 5 vece xd (princeso)
def gestion_empleados(rol):
    while True:
        menu_empleados()
        op = int(input(MSG_INGRESE_OPCION))
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
        op = int(input(MSG_INGRESE_OPCION))
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
    # [DISPONIBILIDAD] Sin try/except: ValueError si el usuario ingresa texto #! Un puto try más por errores con los int y input
    opAuth = int(input(MSG_INGRESE_OPCION))
    if opAuth == 1:
        usuario_actual = iniciar_sesion()
        if usuario_actual:
            rol_actual = usuario_actual["rol"]
            input("Presiona ENTER para ingresar al Sistema RRHH.")
            while True:
                menu_principal(rol_actual)
                op = int(input(MSG_INGRESE_OPCION))
                if op == 1:
                    gestion_empleados(rol_actual)
                elif op == 2:
                    gestion_departamentos(rol_actual)
                elif op == 3:
                    calcular_liquidacion(rol_actual)
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
            break
    elif opAuth == 2:
        registrar_usuario_rrhh()
    elif opAuth == 3:
        op_salir = input("¿DESEA SALIR [SI/NO]: ")
        if op_salir.lower() == "si":
            break
    else:
        print(MSG_OPCION_FUERA_DE_RANGO)