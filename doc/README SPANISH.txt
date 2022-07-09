Buenas, leyendo el libro “The Rootkit Arsenal: Escape and Evasion in the Dark Corners of the System” quería matizar un par de cosas sobre el capítulo “Hooking the GDT - Installing a Call Gate”. Al final del artículo se incluye un POC driver con el soporte del WalkGDT para varios COREs entre otras.

Una Call Gate es un mecanismo en la arquitectura x86 de Intel para cambiar el nivel de privilegio de la CPU cuando se ejecuta una función predefinida llamada mediante una instrucción CALL/JMP FAR.

Una llamada a una Call Gate permite obtener un privilegio superior al actual, por ejemplo podemos ejecutar con un CALL FAR en ring3 una rutina en ring0. Una Call Gate es una entrada en la GDT (Global Descriptor Table) o en la LDT  (Local Descriptor Table).

Windows no utiliza Call Gates para nada en especial, pero hay malware como el gusano Gurong.A, que instala una Call Gate a través de \Device\PhysicalMemory para ejecutar código en ring0. Un artículo que ya hablaba sobre el tema es “Playing with Windows /dev/(k)mem” de crazylord publicado en la Phrack 59.

Hoy en día no se puede hacer tan fácilmente lo de acceder a /Device/PhysicalMemory, recomiendo leer la presentación de Alex Ionescu  en la RECON 2006 “Subverting Windows 2003 SP1 Kernel Integrity Protection“. También hay ejemplos por la red que usan la API ZwSystemDebugControl para instalar una Call Gate, pero como comenta el artículo de Ionescu tampoco funciona hoy en día (aunque siempre hay técnicas para reactivarlos de nuevo).

IMHO, la mejor manera para instalar una Call Gate es un driver como lo hace el ejemplo del libro Rootkit Arsenal, ahora voy a explicar el ejemplo que trae y añadir algunas cosas que veo que faltan:
Una entrada en la GDT tiene esta pinta:
Code (c)

typedef struct _SEG_DESCRIPTOR
{
WORD size_00_15;
WORD baseAddress_00_15;
WORD baseAddress_16_23:8;
WORD type:4;
WORD sFlag:1;
WORD dpl:2;
WORD pFlag:1;
WORD size_16_19:4;
WORD notUsed:1;
WORD lFlag:1;
WORD DB:1;
WORD gFlag:1;
WORD baseAddress_24_31:8;
} SEG_DESCRIPTOR, *PSEG_DESCRIPTOR;

Y una Call Gate es un tipo de entrada en la GDT con el siguiente aspecto:
Code (c)

typedef struct _CALL_GATE_DESCRIPTOR
{
WORD offset_00_15;
WORD selector;
WORD argCount:5;
WORD zeroes:3;
WORD type:4;
WORD sFlag:1;
WORD dpl:2;
WORD pFlag:1;
WORD offset_16_31;
} CALL_GATE_DESCRIPTOR, *PCALL_GATE_DESCRIPTOR;

offset_00_15: es la parte baja de la dirección de la rutina que se ejecutará en ring0, offset_16_31 es la parte alta.

selector: especifica el segmento de código, con el valor KGDT_R0_CODE (0×8), la rutina se ejecutará con privilegios de ring0.

argCount: es el número de argumentos de la rutina en DWORDs.

type: es el tipo de descriptor, para una Call Gate de 32 bits necesita el valor 0xC

dpl: es el privilegio mínimo que debe tener el código que llama para poder ejecutar la rutina, en este caso 0×3, ya que será llamada por una rutina de ring3.

Los pasos para crear una Call Gate son:

   1. Construir la Call Gate que apunte a nuestra rutina.
   2. Leer el registro GDTR para poder encontrar la GDT usando la instrucción: SGDT. El registro GDTR tiene la siguiente pinta:
      Code (c)

      typedef struct _GDTR
      {
      WORD  nBytes;
      DWORD baseAddress;
      } GDTR;

Para obtener el número de entradas en la GDT basta con un GDTR.nBytes / 8.

   1. Buscar una entrada libre en la GDT.
   2. Escribir la Call Gate.

Para llamar a la Call Gate solo es necesario hacer un CALL FAR al selector de la GDT, es decir si hemos introducido la Call Gate en la entrada 0x320 de la GDT, la aplicación de espacio de usuario deberá ejecutar un CALL FAR 0x320:00000000. 0x320 = 1100100000 = Entry:1100100(GDT) TI=0 RPL=00. La otra parte del FAR CALL no sirve para nada pero debe estar en la instrucción.

La rutina de la Call Gate debe salvar los registros: EAX, ECX, EDX, EBX, EBP, ESP, ESI, EDI, EFLAGS y FS. Además debe desactivar las interrupciones con CLI. El selector de FS debe ser 0×30, después solo es necesario restaurar los registros y activar las interrupciones con STI y un RETF si se desea volver a ring3. Todo esto está sacado de nt!KiDebugService() por si te lo estás preguntando.

Bueno y ahora es el momento de los matices, el POC code del libro no tiene en cuenta la posibilidad de existir varios COREs, esto quiere decir que solo es capaz de instalar la Call Gate en el CORE que toque cuando se cargue el driver y la GDT del otro CORE queda intacta, el problema es que si la aplicación de espacio de usuario hace un FAR CALL estando en otro CORE donde no existe la Call Gate no funcionará.

En Windows es sencillo controlar esto con dos APIs: para obtener el número de COREs se puede usar un simple
Code (c)

GetSystemInfo:
void WINAPI GetSystemInfo(
__out  LPSYSTEM_INFO lpSystemInfo
);

Para el número de COREs lógico se puede usar GetLogicalProcessorInformation.
SYSTEM_INFO tiene la siguiente pinta:
Code (c)

typedef struct _SYSTEM_INFO {
…
DWORD     dwNumberOfProcessors;
…
}SYSTEM_INFO;

Con el campo dwNumberOfProcessors podemos realizar un bucle para ir CORE por CORE añadiendo la Call Gate, también se puede forzar al driver a instalar la Call Gate en el primer core (1) y que la aplicación de espacio de usuario solo se ejecute en el core 1, esto se consigue con la API: SetThreadAffinityMask, que es asín:
Code (c)

DWORD_PTR WINAPI SetThreadAffinityMask(
__in  HANDLE hThread,
__in  DWORD_PTR dwThreadAffinityMask
);

Pasándole un GetCurrentThread() y como AffinityMask el valor 1,
Code (c)

Affinity = 1;
SetThreadAffinityMask( GetCurrentThread(), Affinity );

Ojito, DWORD_PTR no es un puntero a DWORD, se pasa por valor.

Si se hace un for con el número de procesadores y con la variable índice (el primero core es 1 no 0) como Affinity puedes instalar una Call Gate en todos los cores. Ten en cuenta que es una máscara, así que debes usar un desplazamiento de bits tipo: AffinityMask = 1 << variable_índice; para recorrer todos los cores.

En el driver que adjunto como POC desde el driver muestro la GDT de todos los COREs para mostrar lo que digo, solo saldrá la Call Gate en un CORE.

Para hacer esto desde un driver es necesario un:
Code (c)

ZwQuerySystemInformation( SystemBasicInformation, & system_basic_information, sizeof( system_basic_information ), NULL );

Para obtener el número de cores y un:
Code (c)

ZwSetInformationThread( (HANDLE) -2, ThreadAffinityMask, & AffinityMask, sizeof( AffinityMask ) );

Para cambiar de core, -2 es el equivalente del GetCurrent…

Otra cosa rara del POC del libro es que pasaba la GDT por valor y no el puntero a PrintGDT y eso me daba problemas, lo he cambiado para que se pase como PSEG_DESCRIPTOR y todo funciona sin problemas.

Y esto es todo, el código es bastante claro, espero que se haya entendido, un saludo desde 48bits.

Descargar el driver desde aquí: http://www.48bits.com/files/cgaty.rar

Driver probado en: XP y VISTA (bin driver: WinDDK 6001.17121 & XP x86 Free build).

Algunas lecturas sobre call gates:

http://www.phrack.com/issues.html?issue=59&id=16
http://en.wikipedia.org/wiki/Call_gate
http://www.intel.com/design/processor/manuals/253668.pdf
http://ricardonarvaja.info/WEB/OTROS/TUTES%20SACCOPHARYNX/
http://members.fortunecity.com/blackfenix/callgates.html
