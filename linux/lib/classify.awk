# ---------------------------------------------------------------------------
# classify.awk
# Clasificacion en lote de artefactos contra la taxonomia de arquitectura.
#
# Motivo de existir: la version PowerShell evalua los patrones artefacto por
# artefacto porque el motor de regex vive dentro del propio proceso. En bash el
# equivalente literal seria un 'grep' por patron y por artefacto: con ~20
# patrones y ~2000 paquetes son 40000 subprocesos, del orden de varios minutos.
# Este script carga la taxonomia una sola vez y resuelve todo el inventario en
# un unico proceso.
#
# ENTRADA  (TSV, por linea): clave <TAB> nombre <TAB> publicador <TAB> ruta
# SALIDA   (TSV, por linea, 11 campos):
#   1 clave        2 rolid       3 rolnombre   4 capaea      5 roldesc
#   6 encatalogo   7 appid       8 appnombre   9 propietario 10 criticidad
#  11 origen
#
# Variables requeridas: apps, roles (rutas TSV), defid, defnom, defcapa, defdesc
#
# Los patrones de arquitectura.json se declaran en minusculas, por lo que la
# comparacion sin distinguir mayusculas se logra bajando el SUJETO a minusculas
# y dejando el patron intacto (bajar el patron romperia clases como [A-Z]).
# ---------------------------------------------------------------------------

BEGIN {
    FS = "\t"; OFS = "\t"

    na = 0
    while ((getline linea < apps) > 0) {
        n = split(linea, f, "\t")
        if (n < 2 || f[2] == "") continue
        na++
        aid[na]   = f[1]; apat[na]  = f[2]; arol[na]  = f[3]; acapa[na] = f[4]
        adesc[na] = f[5]; anom[na]  = f[6]; aprop[na] = f[7]; acrit[na] = f[8]
    }
    close(apps)

    nr = 0
    while ((getline linea < roles) > 0) {
        n = split(linea, f, "\t")
        if (n < 2 || f[2] == "") continue
        nr++
        rid[nr]  = f[1]; rpat[nr] = f[2]; rnom[nr] = f[3]
        rcapa[nr] = f[4]; rdesc[nr] = f[5]
    }
    close(roles)
}

{
    clave  = $1
    nombre = tolower($2)
    sujeto = tolower($2 " " $3 " " $4)

    # Un patron coincide si lo hace contra el NOMBRE solo o contra el sujeto
    # completo (nombre + publicador + ruta). Probar el nombre por separado es
    # imprescindible para los patrones anclados al final, como '^git$' o
    # '.*-dev$': contra el sujeto concatenado nunca podrian coincidir, porque
    # tras el nombre vienen el publicador y la ruta.

    # 1. Catalogo de aplicaciones de negocio (autoridad maxima)
    for (i = 1; i <= na; i++) {
        if (nombre ~ apat[i] || sujeto ~ apat[i]) {
            print clave, arol[i], "Aplicacion de negocio", acapa[i], adesc[i], \
                  "true", aid[i], anom[i], aprop[i], acrit[i], "Catalogo de aplicaciones"
            next
        }
    }

    # 2. Taxonomia de roles, en el orden declarado (la primera coincidencia gana)
    for (i = 1; i <= nr; i++) {
        if (nombre ~ rpat[i] || sujeto ~ rpat[i]) {
            print clave, rid[i], rnom[i], rcapa[i], rdesc[i], \
                  "false", "", "", "", "", "Taxonomia de roles"
            next
        }
    }

    # 3. Sin clasificar
    print clave, defid, defnom, defcapa, defdesc, \
          "false", "", "", "", "", "Sin coincidencia"
}
