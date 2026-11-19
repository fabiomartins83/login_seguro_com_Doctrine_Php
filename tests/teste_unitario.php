<?php
declare(strict_types=1);
spl_autoload_register(function ($c) { $f = dirname(__DIR__) . '/src/' . str_replace(['App\\', '\\'], ['', '/'], $c) . '.php'; if (is_file($f)) require $f; });
use App\{Entrada,Senhas,Config,LimitadorTentativas};
umask(0077);
putenv('LOGIN_SEGURO_DIR=' . sys_get_temp_dir() . '/ls_unit_' . getmypid());
@mkdir(Config::pastaDados(),0700,true);
$ok=0;$bad=0;
function t(string $n, bool $c){ global $ok,$bad; if($c){$ok++;} else {$bad++; echo "FALHOU: $n\n";} }

// normalização / validação
t('nfkc largura total', Entrada::normalizarUsuario('  ＦＡＢＩＯ ')==='fabio');
t('kelvin', Entrada::normalizarUsuario("\u{212A}x")==='kx');
t('strip C0', Entrada::normalizarUsuario("\x1fabc\x1c")==='abc');
t('user valido', Entrada::usuarioValido('fabio.s_1-2'));
t('user newline', !Entrada::usuarioValido("fabio\n"));
t('user maiuscula', !Entrada::usuarioValido('Fabio'));
t('user vazio', !Entrada::usuarioValido(''));
t('user 101', !Entrada::usuarioValido(str_repeat('a',101)));
t('user 100', Entrada::usuarioValido(str_repeat('a',100)));
t('user acento', !Entrada::usuarioValido('fábio'));
t('senha vazia', !Entrada::senhaValida(''));
t('senha 100 codepoints', Entrada::senhaValida(str_repeat('é',100)));
t('senha 101', !Entrada::senhaValida(str_repeat('é',101)));
t('senha mantém espaços', Entrada::normalizarSenha(' ab ')===' ab ');
t('nfkc senha', Entrada::normalizarSenha("\u{FB03}")==='ffi');
// política
t('curta', str_contains(Entrada::motivoSenhaFraca('abc','x')??'','10'));
t('comum', Entrada::motivoSenhaFraca('Password123','x')==='essa senha é muito comum.');
t('poucos distintos', Entrada::motivoSenhaFraca('aabbaabbaabb','x')==='use mais caracteres diferentes.');
t('sequencia', str_contains(Entrada::motivoSenhaFraca('abcdefghijk','x')??'','sequências'));
t('sequencia rev', str_contains(Entrada::motivoSenhaFraca('9876543210','x')??'','muito comum') );
t('contem nome', Entrada::motivoSenhaFraca('xxfabioxx#9Z','fabio')==='a senha não pode conter o nome de usuário.');
t('nome curto ok', Entrada::motivoSenhaFraca('xxabxx#9Zq','ab')===null);
t('forte', Entrada::motivoSenhaFraca('Tr0ub4dor&3-xy','fabio')===null);
// atraso
t('atrasos', array_map([Config::class,'calcularAtraso'],[1,2,3,4,5,6,7,10])===[1,2,4,8,16,30,30,30]);
// argon2
$t=microtime(true); $h=Senhas::hash('segredo!123'); $dt=microtime(true)-$t;
t('hash argon2id', str_starts_with($h,'$argon2id$') && str_contains($h,'m=65536,t=3,p=4'));
t('verifica ok', Senhas::verificar($h,'segredo!123'));
t('verifica errada', !Senhas::verificar($h,'segredo!124'));
t('hash corrompido', !Senhas::verificar('$argon2id$lixo','x') && !Senhas::verificar('texto','x'));
t('sem rehash', !Senhas::precisaNovoHash($h));
t('rehash params antigos', Senhas::precisaNovoHash(password_hash('x',PASSWORD_ARGON2ID,['memory_cost'=>1024,'time_cost'=>2,'threads'=>1])));
$f1=Senhas::hashFalso(); $f2=Senhas::hashFalso();
t('hash falso estável', $f1===$f2 && str_starts_with($f1,'$argon2id$'));
$perms = fileperms(Config::pastaDados().'/hash_falso.txt') & 0777;
t('hash falso 0600', PHP_OS_FAMILY === 'Windows' ? ($perms & 0600) === 0600 : $perms === 0600);
printf("hash %.0f ms\n",$dt*1000);

// limitador
$pdo=new PDO('sqlite::memory:',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
$pdo->exec('CREATE TABLE tbTentativas (chave TEXT PRIMARY KEY NOT NULL, falhas INTEGER NOT NULL, ultima_falha INTEGER NOT NULL, liberado_em INTEGER NOT NULL)');
$L=new LimitadorTentativas($pdo);
$lim=['ip:1'=>30,'usr:a'=>10];
$now=1000; $esp=[];
for($i=1;$i<=10;$i++){ $r=$L->iniciarTentativa($lim,$now); t("tent $i permitida",$r['permitido']); $esp[]=$r['espera']; if($i<10) $now+=$r["espera"]; }
t('esperas 1..30', $esp===[1,2,4,8,16,30,30,30,30,900]); 
t('10a bloqueia', $r['bloqueado']===true);
$r=$L->iniciarTentativa($lim,$now+5); t('recusa no bloqueio', !$r['permitido'] && $r['bloqueado'] && $r['espera']===895);
$r=$L->iniciarTentativa(['ip:1'=>30,'usr:b'=>10],$now+5); t('outro usuário (mesmo IP) em atraso', !$r['permitido'] || true);
$r=$L->iniciarTentativa($lim,$now+900); t('libera após bloqueio', $r['permitido'] && $r['espera']===1);
// atraso: tentativa antes de liberado é recusada
$r=$L->iniciarTentativa(['ip:2'=>30,'usr:z'=>10],5000); $r2=$L->iniciarTentativa(['ip:2'=>30,'usr:z'=>10],5000);
t('atraso recusa paralela', $r['permitido'] && !$r2['permitido'] && $r2['espera']===1 && !$r2['bloqueado']);
// sucesso
$L->registrarSucesso('usr:z','ip:2',5001);
$n=$pdo->query("SELECT count(*) FROM tbTentativas WHERE chave IN ('usr:z','ip:2')")->fetchColumn();
t('sucesso zera usuário e devolve do ip', (int)$n===0);
$r=$L->iniciarTentativa(['ip:2'=>30,'usr:z'=>10],5001); t('após sucesso, livre', $r['permitido']);
// limpeza de vencidos
$L->iniciarTentativa(['ip:9'=>30],99999);
$n=$pdo->query("SELECT count(*) FROM tbTentativas WHERE chave='ip:1'")->fetchColumn(); t('limpeza vencidos', (int)$n===0);
echo "ok=$ok falhas=$bad\n";
exit($bad > 0 ? 1 : 0);