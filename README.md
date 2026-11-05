# Desafio de Elevação de Privilégios no Windows 10

Laboratório prático de **elevação de privilégios local** em uma máquina virtual
Windows 10. Você entra como o usuário comum **`analista`** e precisa encontrar **cinco
caminhos diferentes e independentes** para elevar privilégios até administrador local /
`NT AUTHORITY\SYSTEM`.

Os caminhos **não são indicados**: a proposta é investigar o ambiente em modo *black box*,
encontrar cada falha, explorá-la e obter uma evidência do privilégio alcançado. As cinco
falhas são independentes: cada uma leva à elevação por conta própria.

> Laboratório educacional e autocontido. Explore **somente** esta VM descartável. As
> técnicas aqui servem para estudo de **defesa e hardening** de Windows; não as use fora de
> um ambiente autorizado.

> **Dica:** crie um snapshot chamado **`inicio`** antes de começar e **restaure-o antes de
> testar cada caminho**. Cada vetor deve funcionar sozinho, a partir do estado original.

## Regras da investigação

A atividade é **black box**. Investigue a VM a partir da sessão de `analista`, usando as
ferramentas disponíveis no próprio Windows. Para cada caminho, identifique a condição
vulnerável, execute a exploração e obtenha uma evidência do privilégio alcançado; depois
restaure o snapshot `inicio` e repita para confirmar que aquele caminho funciona por si só.

O objetivo é encontrar e documentar os cinco caminhos. Se não encontrar todos, siga com os
que conseguir, cada um vale por si.

## Solução

Tentou, travou, ou quer conferir sua abordagem? O passo a passo completo dos cinco vetores,
com os comandos e as evidências, está no **[writeup.md](writeup.md)**.

> ⚠️ **Spoiler:** o writeup entrega todos os caminhos. Tente sozinho primeiro, é onde está
> o aprendizado.

Divirta-se e bons estudos.
