(() => {
  'use strict';

  const form = document.getElementById('form-login');
  const campoUsuario = document.getElementById('usuario');
  const campoSenha = document.getElementById('senha');
  const botao = document.getElementById('acessar');
  const mensagem = document.getElementById('mensagem');
  const botaoSair = document.getElementById('sair');

  let relogio = null;

  // Só textContent (nunca innerHTML): nada vindo do servidor é interpretado como HTML
  function exibir(tipo, linhas) {
    mensagem.className = tipo;
    mensagem.hidden = false;
    mensagem.replaceChildren(...linhas.map((texto) => {
      const linha = document.createElement('div');
      linha.textContent = texto;
      return linha;
    }));
  }

  // Espera o atraso imposto pelo servidor (o servidor continua sendo quem decide)
  function aguardar(segundos, bloqueado) {
    clearInterval(relogio);
    botao.disabled = true;
    const linha = document.createElement('div');
    mensagem.appendChild(linha);
    const fim = Date.now() + segundos * 1000;

    const atualizar = () => {
      const restante = Math.ceil((fim - Date.now()) / 1000);
      if (restante <= 0) {
        clearInterval(relogio);
        linha.remove();
        botao.disabled = false;
        return;
      }
      linha.textContent = bloqueado
        ? `Número máximo de tentativas atingido. Tente novamente em ${Math.ceil(restante / 60)} min.`
        : `Aguarde ${restante} s antes de tentar novamente.`;
    };
    atualizar();
    relogio = setInterval(atualizar, 500);
  }

  botaoSair.addEventListener('click', async () => {
    botaoSair.disabled = true;
    try {
      const resposta = await fetch('logout.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: '{}',
        credentials: 'same-origin',
        cache: 'no-store',
      });
      if (!resposta.ok) throw new Error();
      botaoSair.hidden = true;
      mensagem.hidden = true;
      campoUsuario.value = '';
      campoSenha.value = '';
      form.hidden = false;
      campoUsuario.focus();
    } catch {
      exibir('erro', ['Não foi possível sair. Tente novamente.']);
    } finally {
      botaoSair.disabled = false;
    }
  });

  form.addEventListener('submit', async (evento) => {
    evento.preventDefault();
    if (botao.disabled) return;
    botao.disabled = true;

    let esperando = false;
    try {
      const resposta = await fetch(form.getAttribute('action'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ usuario: campoUsuario.value, senha: campoSenha.value }),
        credentials: 'same-origin',
        cache: 'no-store',
      });

      let dados = null;
      try { dados = await resposta.json(); } catch { /* resposta sem JSON */ }

      if (resposta.ok && dados && dados.ok) {
        form.hidden = true;
        exibir('ok', [dados.mensagem]);
        botaoSair.hidden = false;
        return;
      }

      campoSenha.value = '';
      exibir('erro', [(dados && dados.mensagem) || 'Não foi possível concluir o login.']);
      if (dados && dados.aguarde > 0) {
        esperando = true;
        aguardar(dados.aguarde, Boolean(dados.bloqueado));
      }
      campoSenha.focus();
    } catch {
      exibir('erro', ['Não foi possível conectar ao servidor.']);
    } finally {
      if (!esperando) botao.disabled = false;
    }
  });
})();
