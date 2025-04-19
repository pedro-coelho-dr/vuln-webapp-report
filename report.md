

## Vulnerabilidades Encontradas

### 1. Exposição de diretórios sensíveis (Directory Listing)

#### Ponto Afetado

- **URLs acessíveis publicamente:**
  - `http://localhost:5500/js/`
  - `http://localhost:5500/assets/`
  - `http://localhost:5500/css/`
  - `http://localhost:5500/?debug=devtools`

- **Componente afetado:** Estrutura de arquivos do frontend (recursos estáticos)
- **Abrangência:** Toda a aplicação client-side, incluindo scripts críticos e lógicas administrativas

#### Descrição

Durante a fase de reconhecimento, foi possível acessar diretamente os diretórios `/js/`, `/assets/` e `/css`, revelando arquivos e subpastas que deveriam estar protegidos. Essa configuração incorreta do servidor permitiu o recurso conhecido como **directory listing**.

Entre os arquivos expostos, estavam diversos scripts JavaScript essenciais (`utils.js`, `dashboard.js`, `adminMovies.js`, `orders.js`) que revelam detalhes importantes da aplicação, como:

- A existência de um painel administrativo (`dashboard.html`);
- O uso do endpoint `/isAdmin` para checar privilégios;
- A presença de um endpoint oculto (`/devtools`) acessível via parâmetro GET;
- A lógica de autenticação baseada exclusivamente no cookie `token`;
- Os formatos dos payloads enviados ao backend por meio de `fetch()`.

O endpoint `/devtools/` revelou a estrutura interna do backend, incluindo nomes de arquivos sensíveis como `server.py`, `routes.py`, `auth.py`. Embora os conteúdos não estejam diretamente acessíveis, o simples mapeamento da estrutura representa uma exposição significativa que pode facilitar ataques posteriores.

#### Classificação

- **OWASP:** A05:2021 – Security Misconfiguration  
- **CWE:** CWE-548 – Information Exposure Through Directory Listing  

#### Evidências

- Acesso direto ao diretório `/js/`:

  ![](img/dir-list-js.png)

- Listagem da estrutura interna do backend via `?debug=devtools`:

  ![](img/dir-list-devtools.png)

#### Impacto

Essa vulnerabilidade expõe partes sensíveis da lógica da aplicação, facilitando ataques mais precisos e rápidos, como:

- Identificação de rotas e painéis ocultos (ex: `/dashboard.html`, `/admin/orders`, `/admin/stats`)
- Enumeração de funcionalidades administrativas mesmo sem acesso prévio
- Conhecimento da estrutura do backend e nomes de arquivos sensíveis
- Apoio direto a ataques como IDOR, hijacking de sessão, escalonamento de privilégios e bypass de autenticação.

#### Recomendações

- Desabilitar o listamento de diretórios no servidor web.
- Remover arquivos de depuração, como `devtools`, antes da publicação em ambiente de produção.
- Restringir o acesso a diretórios sensíveis apenas a usuários autenticados ou via controle de permissões.
- Considerar o uso de builds minificados/ofuscados para arquivos JavaScript em produção.
- Validar todas as permissões no lado servidor, independentemente de proteções visuais no frontend.

---


### 2. Enumeração de usuários na recuperação de senha

#### Ponto Afetado

- **URL principal de interação:** http://localhost:8000/recover/verify  
- **Parâmetro vulnerável:** Campo `username` submetido via formulário de recuperação de senha  
- **Componente afetado:** Lógica de resposta do backend na verificação de dados  
- **Abrangência:** Funcionalidade de recuperação de senha (afeta todo o sistema de autenticação)

#### Descrição

#### Descrição

O fluxo de recuperação de senha da aplicação apresenta mensagens de erro distintas para cada tipo de falha, o que permite a enumeração de usuários.

Durante os testes, foram observadas duas respostas diferentes ao enviar nomes de usuário no formulário:

- Para um nome inexistente (`carlos`), a resposta foi: "Usuário não encontrado."
- Para um nome existente (`samy`) com dados incorretos, a resposta foi: "Informações incorretas!"

Esse comportamento permite que um atacante utilize o endpoint como um oráculo de verificação, identificando quais nomes de usuário estão cadastrados no sistema, mesmo sem saber outras informações.


#### Classificação

- OWASP: A07:2021 – Identification and Authentication Failures  
- CWE: CWE-204 – Observable Response Discrepancy  

#### Evidências

- Teste com usuário inexistente `carlos`:

    ![](img/user-enum-recover-false.png)

- Teste com usuário existente `samy`, mas dados inválidos:

    ![](img/user-enum-recover-true.png)

#### Impacto

Essa vulnerabilidade permite que um atacante obtenha uma lista parcial ou completa de usuários válidos no sistema, facilitando ataques subsequentes como brute-force, reset de senha direcionado ou spear-phishing. Quando combinado com falhas de autenticação, o impacto é ainda mais severo.

#### Recomendações

- Padronizar as mensagens de erro de forma neutra e genérica.  
- Evitar expor explicitamente se o nome de usuário é válido ou não.  
- Implementar proteção contra automação (ex: rate limiting ou CAPTCHA).  
- Monitorar tentativas de recuperação suspeitas e notificar os usuários em caso de abusos.


---


### 3. Reset de senha sem validação de identidade

#### Ponto Afetado

- **URL principal de interação:** http://localhost:8000/recover/reset  
- **Parâmetros vulneráveis:** `username` e `password` (fornecidos no corpo da requisição)  
- **Componente afetado:** Fluxo de recuperação de senha  
- **Abrangência:** Endpoint crítico exposto sem validação adequada da identidade do usuário

#### Descrição

A aplicação permite redefinir a senha de qualquer usuário apenas com o envio de um nome de usuário válido, sem exigir autenticação ou qualquer vínculo com uma sessão verificada.

A etapa de redefinição (`/recover/reset`) pode ser acessada diretamente via requisição POST, sem depender do fluxo anterior de verificação (`/recover/verify`). Isso permite que um atacante, conhecendo ou adivinhando o nome de usuário, redefina senhas arbitrariamente — incluindo contas privilegiadas como `admin`.

A ausência de validação entre as etapas do fluxo torna o mecanismo de recuperação vulnerável a ataques de escalonamento de privilégio e controle total de contas.


#### Classificação

- OWASP: A07:2021 – Identification and Authentication Failures  
- CWE: CWE-640 – Weak Password Recovery Mechanism for Forgotten Password 

#### Evidências

- Requisição direta ao endpoint de reset usando o nome de usuário `admin`:

  ![](img/reset-password-burp.png)

- Acesso confirmado à conta administrativa após alteração da senha:

  ![](img/reset-password-admin-sucess.png)

#### Impacto

Um atacante que consiga prever ou identificar nomes de usuários válidos pode redefinir suas senhas e assumir suas contas, incluindo contas privilegiadas. Isso compromete a integridade e confidencialidade de toda a aplicação, permitindo acesso irrestrito a dados, funcionalidades e possivelmente o controle administrativo da plataforma.

#### Recomendações

- Associar o processo de recuperação de senha a uma sessão segura temporária vinculada ao usuário verificado.  
- Evitar que a API de reset aceite solicitações diretas sem verificação de identidade.  
- Implementar tokens únicos de recuperação de senha com expiração curta, enviados via canal seguro.
- Incluir registros de auditoria e alertas para qualquer tentativa de recuperação de senha.




---

### 4. Tokens de sessão previsíveis (Time-based)

#### Ponto Afetado

- **URL principal de interação:** http://localhost:8000/login  
- **Parâmetro vulnerável:** Cookie `token` (utilizado na autenticação de sessão)  
- **Componente afetado:** Mecanismo de geração e validação de sessão  
- **Abrangência:** Comportamento sistêmico (todos os tokens gerados compartilham o mesmo padrão frágil)


#### Descrição

Os tokens de sessão da aplicação são gerados com base em `time.time()`, utilizando o timestamp atual em segundos desde a época UNIX. Essa abordagem torna os tokens altamente previsíveis, permitindo que um atacante estime o momento do login e gere tokens válidos por tentativa.

Durante os testes, um script automatizado foi capaz de identificar múltiplos tokens ativos utilizando essa técnica.

Além disso, foi observado que a aplicação gera um token já no primeiro acesso, antes do login. Esse mesmo token é reaproveitado após a autenticação, sem renovação, o que agrava a previsibilidade e cria um cenário de session fixation.


#### Classificação

- OWASP: A2:2021 – Broken Authentication

- CWE: CWE-341 – Predictable Pseudo-Random Number Generator


#### Evidências

- Script em Python para geração de tokens válidos:  
  
    [script.py](script.py)


- Múltiplos tokens válidos identificados com sucesso:

    ![](img/token-predict-script.png)



#### Impacto
Essa vulnerabilidade permite que um atacante consiga prever tokens de usuários que realizaram login recentemente, permitindo o acesso não autorizado a sessões ativas. Dependendo do perfil acessado, isso pode comprometer totalmente a aplicação e os dados dos usuários, incluindo contas administrativas.

#### Recomendações

- Substituir o mecanismo de geração de tokens por um gerador criptograficamente seguro.
- Evitar qualquer mecanismo baseado apenas em timestamps.



---

### 5. Sequestro de sessão e session fixation

#### Ponto Afetado

- **URLs afetadas:** Todas as rotas autenticadas (ex: `/movies`, `/admin/stats`, etc.)  
- **Parâmetro vulnerável:** Cookie `token`  
- **Componente afetado:** Validação da sessão no backend  
- **Abrangência:** Comportamento sistêmico (qualquer token válido pode ser reutilizado sem contexto adicional)


#### Descrição

A aplicação aceita qualquer token válido como meio de autenticação, sem verificar sua origem, contexto ou validade temporal. Isso permite sequestro de sessão (session hijacking) com a simples reutilização de um token previamente emitido.

Não há proteção contra reutilização do token em navegadores ou dispositivos diferentes, nem vínculo com informações da sessão original (como IP ou user-agent).

Além disso, o token gerado no primeiro acesso — antes mesmo do login — continua ativo após a autenticação, sem rotação. Esse comportamento caracteriza um cenário clássico de session fixation.

Durante os testes, foi possível reutilizar um token válido (`1745015987`) em uma nova aba anônima e obter acesso direto ao painel administrativo.


#### Classificação

- OWASP: A01:2021 – Broken Access Control  
- CWE: CWE-384 – Session Fixation  

#### Evidências

- Cookie com token `1745015987` reutilizado com sucesso fora da sessão original:

    ![](img/session-hijacking-dashboard-dev.png)

#### Impacto

Um atacante que obtenha qualquer token de sessão válido poderá assumir completamente a identidade do usuário, sem a necessidade de conhecer as credenciais. Isso pode incluir usuários privilegiados como administradores, expondo dados sensíveis e funções críticas.

#### Recomendações

- Utilizar identificadores de sessão aleatórios com entropia suficiente (UUID, `secrets.token_urlsafe` etc).  
- Associar sessões a fingerprints de cliente (ex: IP, User-Agent).  
- Implementar expiração e rotação periódica de tokens.  
- Adicionar suporte a logout remoto e invalidação imediata do token após logout.  
- Sinalizar cookies com `HttpOnly`, `Secure` (em HTTPS) e `SameSite=Strict`.




---
### 6. Enumeração de privilégios via `/isAdmin`

#### Ponto Afetado

- **URL de interação:** `http://localhost:8000/isAdmin`  
- **Parâmetro vulnerável:** Cookie `token` (identificador de sessão)  
- **Componente afetado:** Lógica de verificação de privilégios administrativos  
- **Abrangência:** Toda a aplicação, com especial foco na enumeração de contas privilegiadas


#### Descrição

O endpoint `/isAdmin` retorna `true` ou `false` indicando se o token da sessão atual pertence a um usuário administrador. Essa verificação está acessível a qualquer cliente autenticado, sem restrições adicionais.

Esse comportamento pode ser explorado por um atacante que esteja testando tokens — por exemplo, tokens gerados com base em tempo — para identificar quais pertencem a contas privilegiadas. Com isso, é possível priorizar tokens administrativos em ataques de hijacking.

A exposição dessa informação representa uma forma de disclosure de privilégios e falha de controle de acesso, ao revelar a natureza do usuário sem necessidade real.


#### Classificação

- OWASP: A01:2021 – Broken Access Control  
- CWE: CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor  

#### Evidências

- **Resposta do endpoint `/isAdmin` ao testar tokens obtidos por brute-force:**

  ![](img/admin-enum-repeater.png)

- **Script de automação usado para filtrar tokens com privilégios administrativos:**

  ![](img/admin-enum-script.png)


#### Impacto

Permite que um atacante identifique quais tokens estão associados a contas administrativas, mesmo sem realizar login ou obter outras credenciais. Isso facilita ataques dirigidos de session hijacking, privilege escalation e uso de endpoints sensíveis da aplicação com privilégios elevados.

#### Recomendações

- Restringir o endpoint `/isAdmin` apenas para usuários autenticados que precisem dessa informação no contexto de suas ações (idealmente apenas no backend).
- Retornar mensagens genéricas (ou HTTP 403) para usuários não autorizados, em vez de `true/false`.
- Realizar verificação de privilégios exclusivamente no backend, e não expor a lógica ao frontend de forma direta.
- Monitorar acessos frequentes ou suspeitos ao endpoint `/isAdmin`.



---
### 7. IDOR – Modificação e exclusão de dados de terceiros

#### Ponto Afetado

- **URLs principais de interação:**
  - `http://localhost:8000/edit-username`
  - `http://localhost:8000/edit-email`
  - `http://localhost:8000/edit-phone`
  - `http://localhost:8000/delete_user`

- **Parâmetro vulnerável:** Campo `id` enviado no corpo da requisição

- **Componente afetado:** Endpoints de manipulação de dados sensíveis de usuários

- **Abrangência:** Qualquer usuário autenticado pode modificar ou excluir dados de qualquer outro usuário, conhecendo seu ID


#### Descrição

A aplicação permite que usuários autenticados modifiquem ou excluam dados de outras contas ao manipular o campo `id` nas requisições, sem validação de permissões no backend. Esse comportamento caracteriza uma falha de IDOR (Insecure Direct Object Reference).

Durante os testes, foi possível:

- Alterar o nome de usuário, e-mail e telefone de outros usuários;
- Excluir permanentemente uma conta utilizando o endpoint `/delete_user`, mesmo sem privilégios administrativos.

O endpoint de exclusão não realiza nenhuma checagem de autorização, permitindo que qualquer usuário remova contas arbitrárias.


#### Classificação

- **OWASP:** A01:2021 – Broken Access Control  
- **CWE:** CWE-639 – Authorization Bypass Through User-Controlled Key  

#### Evidências

- Requisição alterando o nome de outro usuário (`id = 05`):  
  ![](img/idor-edit-username.png)

- Visualização da alteração no painel administrativo:  
  ![](img/idor-success.png)

- Exclusão de usuário executada com sucesso sem ser administrador:  
  ![](img/idor-delete-user.png)

#### Impacto

Essas vulnerabilidades permitem que qualquer usuário autenticado:

- **Altere dados de outras contas**
- **Apague contas inteiras**, inclusive administrativas
- **Obstrua o funcionamento normal da aplicação**
- **Facilite ataques futuros**, como redefinições de senha ou negação de serviço

#### Recomendações

- Implementar checagens rígidas de autorização no backend: somente **o próprio usuário ou um administrador** devem poder modificar/excluir contas.
- Remover o parâmetro `id` das requisições e utilizar o identificador da **sessão autenticada**.
- Adicionar **logs de auditoria** para rastrear ações sensíveis como exclusão de usuários.
- Retornar **erros claros e seguros** em caso de tentativa de ação não autorizada.




---
### 8. Manipulação de preço via parâmetro client-side

#### Ponto Afetado

- **URL principal de interação:** `http://localhost:8000/order`  
- **Parâmetro vulnerável:** `total_price` (enviado no corpo da requisição POST)  
- **Componente afetado:** Backend de criação de pedidos  
- **Abrangência:** Toda a lógica de pedidos e faturamento da aplicação

#### Descrição

#### Descrição

O endpoint de criação de pedidos (`/order`) aceita o valor do campo `total_price` diretamente do cliente, sem validação ou cálculo no backend. Esse valor é gravado no banco e exibido como o preço oficial do pedido na interface administrativa.

Durante os testes, foi possível alterar esse campo para R$ 0,00 e realizar a compra normalmente, indicando ausência total de verificação no servidor.

Essa lógica transfere uma etapa crítica de negócio para o lado do cliente, permitindo fraudes, inconsistência nos registros financeiros e comprometimento da integridade dos dados.


#### Classificação

- OWASP: A04:2021 – Insecure Design  
- CWE: CWE-345 – Insufficient Verification of Data Authenticity  


#### Evidências

- Pedido manipulado com `total_price: 0`, aceito com sucesso:

  ![alt text](img/order-repeater.png)
  ![alt text](img/order-site.png)
  ![alt text](img/order-site2.png)

#### Impacto

Um atacante pode realizar pedidos gratuitos ou com valores artificiais, comprometendo a confiabilidade do sistema de cobrança, os registros administrativos e a integridade financeira da aplicação.

Essa falha permite fraudes silenciosas, manipulação e perdas financeiras.

#### Recomendações

- Ignorar qualquer valor enviado pelo cliente para o campo `total_price`.  
- Calcular o preço exclusivamente no backend com base em regras internas.  
- Validar consistência dos dados antes de gravar no banco.  



---
### 9. Ausência de MFA, brute-force protection e auditoria

#### Ponto Afetado

- **Componentes afetados:** Autenticação (`/login`), redefinição de senha (`/recover/reset`), alteração de dados pessoais (`/edit-*`)  
- **Abrangência:** Toda a aplicação, afetando os fluxos de autenticação, recuperação e alteração de informações


#### Descrição

A aplicação não implementa mecanismos essenciais de proteção para os fluxos de autenticação e recuperação de conta, deixando usuários e administradores vulneráveis a ataques comuns.

Foram observadas as seguintes falhas:

- Ausência de proteção contra brute-force: É possível realizar múltiplas tentativas de login sem qualquer tipo de limitação, como rate limiting, CAPTCHA ou bloqueio temporário.

- Ausência de autenticação multifator (MFA): Não há suporte a segundo fator de autenticação, nem mesmo para contas administrativas.

- Ausência de notificações ou trilhas de auditoria: A aplicação não informa os usuários sobre eventos críticos, como logins, tentativas falhas, alterações de senha ou mudanças em dados sensíveis.

- Uso de perguntas pessoais na recuperação de senha: A redefinição de senha depende exclusivamente de perguntas como "cor favorita" ou "escola", que são informações facilmente dedutíveis ou disponíveis via engenharia social.


#### Classificação

- OWASP: A07:2021 – Identification and Authentication Failures  
- CWE:  
  - CWE-307 – Improper Restriction of Excessive Authentication Attempts  
  - CWE-521 – Weak Password Requirements  
  - CWE-306 – Missing Authentication for Critical Function
  - CWE-640 – Weak Password Recovery Mechanism for Forgotten Password

#### Evidências

- Tentativas de login ilimitadas sem bloqueio observado
- Nenhuma comunicação recebida por e-mail após ações críticas
- Ausência de campo ou interface para MFA em todo o fluxo da aplicação

#### Impacto

A falta desses mecanismos compromete tanto a **confidencialidade** quanto a **integridade** das contas dos usuários. Isso facilita:

- Ataques automatizados de brute-force;
- Uso indevido de sessões ativas por terceiros;
- Ataques de engenharia social com base em alterações silenciosas de dados.

#### Recomendações

- Implementar rate limiting** e bloqueios temporários após número excessivo de tentativas de login;
- Adicionar autenticação multifator (por e-mail, TOTP ou SMS);
- Enviar notificações por e-mail e/ou registrar auditoria para ações críticas;
- Aplicar política de senha forte, incluindo mínimo de caracteres e complexidade.