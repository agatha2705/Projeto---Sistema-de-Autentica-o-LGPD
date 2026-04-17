# Projeto Integrador – Políticas de Segurança da Informação
 
## Sobre o Projeto
 
Este projeto foi desenvolvido como parte da atividade da disciplina Políticas de Segurança da Informação, com o objetivo de aplicar na prática os conhecimentos estudados ao longo do curso. A proposta consistiu na criação de um sistema seguro de autenticação e gerenciamento de credenciais, utilizando tecnologias atuais e seguindo princípios da LGPD (Lei Geral de Proteção de Dados).
 
O sistema foi projetado para oferecer mais segurança no acesso dos usuários, protegendo informações sensíveis e reduzindo riscos comuns como vazamento de senhas, acessos indevidos e tentativas de invasão.
 
## Objetivo do Sistema
 
Desenvolver, implementar, documentar e comunicar cientificamente um sistema seguro de autenticação e gestão de credenciais, incorporando autenticação multifator, criptografia, recuperação segura de senhas, auditoria e conformidade com a LGPD, com fundamentação em normas técnicas e literatura científica revisada por pares. 
 
## Tecnologias Utilizadas
 
O desenvolvimento foi realizado utilizando Python como linguagem principal, com o framework Flask para construção da aplicação web. O banco de dados utilizado foi o MySQL, responsável pelo armazenamento das credenciais e informações dos usuários.
 
Também foram utilizadas bibliotecas específicas de segurança, como bcrypt para criptografia de senhas, PyOTP para autenticação em dois fatores via código temporário e QRCode para geração do QR Code utilizado no Google Authenticator.
 
## Estrutura do Projeto
 
│── app.py
│── sistema de autenticacao.py
│── requirements.txt
│── .env
│── templates/
│   ├── login.html
│   ├── cadastro.html
│   ├── 2fa.html
│   ├── qr.html
│   ├── dashboard.html
│   ├── recuperacao.html
│   └── resetar.html
 
O sistema é composto por arquivos principais responsáveis pela lógica da aplicação, dependências e páginas web.
 
- app.py – aplicação principal em Flask  
- sistema de autenticacao.py – versão complementar em terminal  
- requirements.txt – bibliotecas utilizadas  
- templates/ – páginas HTML do sistema  
 
## Funcionalidades Implementadas
 
O sistema permite que novos usuários realizem cadastro com validação de e-mail e definição de senha forte. Para aumentar a segurança, a senha precisa conter no mínimo oito caracteres, letra maiúscula, número e caractere especial. Após o cadastro, a senha não é armazenada em texto puro, sendo protegida com criptografia utilizando bcrypt.
 
No processo de login, o sistema verifica as credenciais informadas e também possui proteção contra tentativas repetidas de acesso. Caso ocorram cinco erros consecutivos, a conta é bloqueada temporariamente por cinco minutos, reduzindo riscos de ataques por força bruta.
 
Após a validação correta da senha, é exigida uma segunda etapa de autenticação. O usuário recebe uma chave vinculada ao aplicativo Google Authenticator por meio de QR Code e deve informar o código temporário gerado no aplicativo. Também são disponibilizados códigos de backup para casos de perda de acesso ao autenticador.
 
Outro recurso implementado é o gerenciamento seguro de sessões. Após o login, a sessão permanece ativa por tempo limitado e pode ser encerrada manualmente pelo usuário através do logout. O sistema também impede o cache de páginas protegidas, evitando acesso indevido após o encerramento da sessão.
 
Além disso, foi criada uma funcionalidade inicial de recuperação de senha, permitindo redefinir o acesso por meio de token temporário, mas que ainda será refinada nos próximos passos.
 
## Aplicação da LGPD
 
O projeto foi desenvolvido considerando princípios importantes da LGPD, especialmente no tratamento seguro de dados pessoais. O sistema coleta apenas informações necessárias para funcionamento, como e-mail e senha criptografada, evitando excesso de dados armazenados.
 
Também foram adotadas medidas técnicas de proteção, como criptografia, autenticação reforçada e controle de acesso, contribuindo para a privacidade e segurança das informações dos usuários.
 
 
## Conclusão
 
O desenvolvimento deste projeto permitiu aplicar conceitos essenciais de segurança da informação em uma solução prática e funcional. A aplicação demonstra como mecanismos como criptografia, autenticação em dois fatores, controle de sessões e proteção contra ataques podem tornar sistemas mais seguros.
 
Dessa forma, o trabalho atende ao objetivo proposto pela disciplina e reforça a importância da implementação de boas práticas de segurança e conformidade com a LGPD em sistemas modernos.

Para melhor visualização, apresentamos abaixo os testes realizados nas interfaces de cadastro, login e configuração de autenticação de dois fatores (2FA), e a tela de boas-vindas pós-autenticação do usuário.

<img width="1781" height="988" alt="image" src="https://github.com/user-attachments/assets/752e1b97-fa70-4a98-ba2c-3612a9c0f75d" />
