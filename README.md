# kohunt 🐛🔫

Conduce drivers Linux `.ko` **reales** dentro de [mwemu](../mwemu) en modo kernel
y saca fallos de memoria del *slab ledger*: use-after-free, double-free,
slab-out-of-bounds y leaks.

La idea: mwemu es dueño del slab, así que un chunk liberado queda en cuarentena y
envenenado, y **cada acceso se comprueba**. Fallando el N-ésimo `kmalloc`
(fault-injection) se conducen las rutas de error/cleanup, donde vive la mayoría
de double-frees y UAFs de driver.

```
kohunt <modo> <fichero.ko | dir> [cap]
```

- **`<modo>`** — uno de los de la tabla de abajo (`init`, `probe`, `wps`, …).
- **`<fichero.ko | dir>`** — un `.ko`/`.ko.zst` (descomprime al vuelo) o un
  directorio: lo recorre recursivamente y ejecuta el modo sobre cada módulo.
- **`[cap]`** — tope de allocs a fault-injectar por función (por defecto **48**).

### El parámetro `cap`

Los modos genéricos hacen *allocation-failure injection*: para cada `kmalloc`
del módulo, se reejecuta la función haciendo fallar ese alloc y solo ese, para
recorrer la rama de error/cleanup que cuelga de él. `cap` limita cuántos allocs
distintos se recorren así: se prueban `min(nº_allocs_observados, cap)` índices
(0, 1, 2, …). Subirlo cubre más rutas de cleanup a costa de más tiempo; bajarlo
acelera un barrido amplio. **Solo aplica a `init` y `probe`**; los modos de
parser (`wps`, `loop`, `uvc`, `hid`, `l2cap`) lo ignoran.

### Ejemplos

```sh
kohunt init  /lib/modules/$(uname -r)/kernel   # barrido masivo, cap 48
kohunt probe ~/lab/ko/r8723bs.ko               # conduce el probe real capturado
kohunt init  ~/lab/ko/fnic.ko 200              # cleanup a fondo: hasta 200 allocs
kohunt wps   ~/lab/ko/r8723bs.ko               # PoC del overflow WPS (ignora cap)
```

## Modos

| Modo    | Genérico | Qué hace |
|---------|:--------:|----------|
| `init`  | ✅ | Corre `init`+`exit` y fault-injecta cada alloc para forzar el cleanup. |
| `probe` | ✅ | Captura el `.probe` real + `id_table` del driver registrado y lo conduce con fault-injection. |
| `wps`   | ❌ | Dispara `rtw_get_wps_attr_content` (rtl8723bs) con un IE WPS currado → stack overflow remoto. |
| `loop`  | ❌ | Comprueba el wrap `u16` en el walker de atributos WPS (bucle infinito). |
| `uvc`   | ❌ | Conduce `uvc_parse_standard_control` con descriptores USB-video currados. |
| `hid`   | ❌ | Conduce `hid_open_report` con report-descriptors HID currados. |
| `l2cap` | ❌ | Conduce `l2cap_parse_conf_req/rsp` con opciones de config Bluetooth curradas. |

Los modos genéricos funcionan sobre cualquier `.ko`. Los demás son plantillas de
*parser fuzzing* dirigido: fijan la firma y los offsets de una función concreta.

## Funciones (`src/main.rs`)

- `is_interesting` — filtra los reportes del ledger que son fallos reales (UAF, double-free, OOB, poison).
- `fresh` — crea un emulador, carga el `.ko` y lo deja listo (límites, banzai, skip de APIs no implementadas).
- `probe_symbols` — heurística por nombre para hallar entradas tipo `probe`/`init_one`/`_attach` cuando no hubo captura.
- `run_probe` — ejecuta una llamada a probe bajo un índice de fault dado; devuelve findings y nº de allocs.
- `probe_entries` — prefiere el probe real capturado en `*_register_driver`; cae a la heurística de nombres si no hay captura.
- `drive_probe` — modo `probe`: barre baseline + fault-injection sobre cada punto de entrada.
- `report` — imprime un finding formateado y suma al contador de hits.
- `indent` — indenta un texto multilínea (helper de presentación).
- `drive_init` — modo `init`: carga limpia + teardown, y fault-injection sobre la ruta de cleanup del init.
- `collect_ko` — recolecta recursivamente los `.ko`/`.ko.zst` bajo un fichero o directorio.
- `materialize` — devuelve un `.ko` real, descomprimiendo antes un `.ko.zst` a un temporal.
- `drive_wps` — modo `wps`: IE WPS con atributo de 100 bytes contra un destino de 1 byte → slab-out-of-bounds.
- `drive_loop` — modo `loop`: atributo con `data_len=0xFFFC` que hace wrap del `u16` → detecta bucle infinito midiendo instrucciones.
- `run_uvc_case` — monta un `uvc_device` deref-safe y conduce `uvc_parse_standard_control` con un descriptor.
- `drive_uvc` — modo `uvc`: lanza varios casos (input-terminal, extension-unit) sobre el parser UVC.
- `run_hid_case` — monta un `hid_device` y conduce `hid_open_report` con un report-descriptor.
- `drive_hid` — modo `hid`: batería de report-descriptors (bisección, counts/sizes grandes, colecciones anidadas).
- `run_l2cap_case` — monta un `l2cap_chan` y conduce `l2cap_parse_conf_req` con opciones de config.
- `drive_l2cap` — modo `l2cap`: casos de `parse_conf_req` y `parse_conf_rsp` (MTU, len sobredimensionado, multi-opción).
- `run_l2cap_rsp_case` — conduce `l2cap_parse_conf_rsp` con una respuesta de config currada.
- `main` — parsea args, recolecta módulos y despacha al modo elegido (con `catch_unwind` por módulo).

## Estado del hunt

Ver las notas de progreso en la memoria del proyecto. Hallazgo confirmado hasta
la fecha: **stack overflow remoto en `rtw_get_wps_attr_content` (rtl8723bs)** vía
atributo WPS "Selected Registrar" — reproducible con `kohunt wps r8723bs.ko`.
