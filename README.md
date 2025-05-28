Levich Documentation

Deployment Links

Frontend GIthub link: https://github.com/robinrdj/levichfrontend 

Backend GIthub link: https://github.com/robinrdj/levichbackend 

Frontend Deployed link: https://levichfrontend.vercel.app/ 

Backend Deployed link: https://levichbackend.onrender.com/

—----------------------------------------------------------------------------------------------------------------------------

Setup Instructions For frontend Installation Steps 

1.Clone repo & install dependencies 

git clone 

cd 

npm install 

2.Start server npm start

For backend Requirements Node.js MongoDB (local or Atlas) .env file with the following: ACCESS_SECRET= your_jwt_secret REFRESH_SECRET= your_jwt_secret RESET_PASSWORD_SECRET= your_jwt_secret FRONTEND_URL= your_frontend_url MONGO_URI= your_mongo_uri Installation Steps 

1.Clone repo & install dependencies  

git clone 

cd npm install 

2.Start MongoDB Locally: 

mongod

Or use MongoDB Atlas and update MONGO_URI in .env.

3.Start server 

node index.js

—----------------------------------------------------------------------------------------------------------------------------

API Documentation

Auth Routes (/auth) Method Endpoint Description Access POST api/auth/signup Register a new user Public POST api/auth/login Authenticate and get token Public POST api/auth/permissions Promote to admin Authenticated

Comment Routes (/comments) Method Endpoint Description Access GET api/comments List all comments Public POST api/comments Add new comment Authenticated (write) DELETE api/comments/:id Delete a comment (admin or owner) Authenticated (deleteAny)

User Permissions Role Permissions guest read user read, write admin read, write, deleteAny

—------------------------------------------------------------------------------------------------------------------

Curl Commands for testing The following curl commands works in: Linux/macOS terminals

Git Bash / WSL / Bash on Windows Auth routes Sign Up 

curl -X POST https://levichbackend.onrender.com/api/auth/signup
-H "Content-Type: application/json"
-d '{ "name": "John Hyn", "email": "johnhyn@example.com", "password": "1az2vf3bg45ef6" }'

You will get {"message":"User created"}

—------------------------------------------------

----------------------

note:
the access token provided here as an example won't work

-----------------
Login 

curl -X POST https://levichbackend.onrender.com/api/auth/login
-H "Content-Type: application/json"
-d '{ "email": "johnhyn@example.com", "password": "1az2vf3bg45ef6" }'

You will get {"accessToken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4MzY1Mzc2OTAzMTNlYTkzYWRmYzFjNyIsIm5hbWUiOiJKb2huIEh5bjEiLCJlbWFpbCI6ImpvaG5oeW4xQGV4YW1wbGUuY29tIiwicm9sZSI6InVzZXIiLCJwZXJtaXNzaW9ucyI6WyJyZWFkIiwid3JpdGUiXSwiaWF0IjoxNzQ4MzkwOTg0LCJleHAiOjE3NDg0NzczODR9.fZwdPWC2tdw6LlZ4_F5mkx8MsCTnAhOv_VR6ZND-6g0","user":{"_id":"6836537690313ea93adfc1c7","name":"John Hyn1","email":"johnhyn1@example.com","password":"$2b$10$4wdr/fns5/0CUUlqiv2TiOxmPoFKDisi3RrMX06lWIhn9d0WLGQLq","role":"user","permissions":["read","write"],"__v":0,"refreshToken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4MzY1Mzc2OTAzMTNlYTkzYWRmYzFjNyIsImlhdCI6MTc0ODM5MDk4NCwiZXhwIjoxNzUwOTgyOTg0fQ.lU5Oja0P700zeuJraudQ2ILHFkz6d01Xb_XbvP7oLwU"}}

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4MzY1Mzc2OTAzMTNlYTkzYWRmYzFjNyIsIm5hbWUiOiJKb2huIEh5bjEiLCJlbWFpbCI6ImpvaG5oeW4xQGV4YW1wbGUuY29tIiwicm9sZSI6InVzZXIiLCJwZXJtaXNzaW9ucyI6WyJyZWFkIiwid3JpdGUiXSwiaWF0IjoxNzQ4MzkwOTg0LCJleHAiOjE3NDg0NzczODR9.fZwdPWC2tdw6LlZ4_F5mkx8MsCTnAhOv_VR6ZND-6g0

—------------------------------------------------

Change Role to Admin 

curl -X POST https://levichbackend.onrender.com/api/auth/permissions
-H "Content-Type: application/json"
-H "Authorization: Bearer <ACCESS_TOKEN>"
-d '{"email": "johnhyn@example.com"}'


Example command with access token: curl -X POST https://levichbackend.onrender.com/api/auth/permissions
-H "Content-Type: application/json"
-H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4MzY1Mzc2OTAzMTNlYTkzYWRmYzFjNyIsIm5hbWUiOiJKb2huIEh5bjEiLCJlbWFpbCI6ImpvaG5oeW4xQGV4YW1wbGUuY29tIiwicm9sZSI6InVzZXIiLCJwZXJtaXNzaW9ucyI6WyJyZWFkIiwid3JpdGUiXSwiaWF0IjoxNzQ4MzkwOTg0LCJleHAiOjE3NDg0NzczODR9.fZwdPWC2tdw6LlZ4_F5mkx8MsCTnAhOv_VR6ZND-6g0"
-d '{"email": "johnhyn@example.com"}'

You will get {"message":"Role & permissions updated","permissions":["read","write","deleteAny"]}

—------------------------------------------------

Comment routes To get all comments(public) 

curl https://levichbackend.onrender.com/api/comments

—------------------------------------------------

Post a Comment (auth required) 

curl -X POST https://levichbackend.onrender.com/api/comments
-H "Authorization: Bearer <your_token_here>"
-H "Content-Type: application/json"
-d '{ "text": "This is a comment" }'

Example command with access token: curl -X POST https://levichbackend.onrender.com/api/comments
-H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4MzY1Mzc2OTAzMTNlYTkzYWRmYzFjNyIsIm5hbWUiOiJKb2huIEh5bjEiLCJlbWFpbCI6ImpvaG5oeW4xQGV4YW1wbGUuY29tIiwicm9sZSI6InVzZXIiLCJwZXJtaXNzaW9ucyI6WyJyZWFkIiwid3JpdGUiXSwiaWF0IjoxNzQ4MzkwOTg0LCJleHAiOjE3NDg0NzczODR9.fZwdPWC2tdw6LlZ4_F5mkx8MsCTnAhOv_VR6ZND-6g0"
-H "Content-Type: application/json"
-d '{ "text": "This is a comment by john" }'

You will get {"text":"This is a comment by john","userId":"6836537690313ea93adfc1c7","_id":"683655f990313ea93adfc1ce","__v":0}

—------------------------------------------------

Delete a Comment (admin ) Note: U should be an admin to have this functionality otherwise it won’t work. Do the change role to admin step first before running this command

curl -X DELETE https://levichbackend.onrender.com/api/comments/<comment_id>
-H "Authorization: Bearer <your_token_here>"

Example command with access token and comment_id: Comment_id is the _id you got in the previous step highlighted in orange.

curl -X DELETE https://levichbackend.onrender.com/api/comments/"683655f990313ea93adfc1ce"
-H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4MzY1Mzc2OTAzMTNlYTkzYWRmYzFjNyIsIm5hbWUiOiJKb2huIEh5bjEiLCJlbWFpbCI6ImpvaG5oeW4xQGV4YW1wbGUuY29tIiwicm9sZSI6InVzZXIiLCJwZXJtaXNzaW9ucyI6WyJyZWFkIiwid3JpdGUiXSwiaWF0IjoxNzQ4MzkwOTg0LCJleHAiOjE3NDg0NzczODR9.fZwdPWC2tdw6LlZ4_F5mkx8MsCTnAhOv_VR6ZND-6g0"

Note: the comment_id should be present within strings as shown in the example

result: Now u can check the comments and it will be deleted.

Similarly you could check for the password routes

—------------------------------------------------

Password routes 
Forgot password 

curl -X POST https://levichbackend.onrender.com/api/auth/forgot
-H "Content-Type: application/json"
-d '{ "email": "john@example.com" }'

You will get {"message":"Reset link generated","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4MzY1Mzc2OTAzMTNlYTkzYWRmYzFjNyIsImlhdCI6MTc0ODM5NDYzNCwiZXhwIjoxNzQ4Mzk1NTM0fQ.B9MTar6QOnuuRnqtobOSLD4EAoQfERmwAxvkzwgekfw"}

Reset password 

curl -X POST https://levichbackend.onrender.com/api/auth/reset/<TOKEN_FROM_FORGOT_PASSWORD_REQUEST>
-H "Content-Type: application/json"
-d '{ "password": "newSecurePassword123" }'

Replace the token you received from the forgot password command which is in orange color in <TOKEN_FROM_FORGOT_PASSWORD_REQUEST>.

Example command 

curl -X POST https://levichbackend.onrender.com/api/auth/reset/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4MzY1Mzc2OTAzMTNlYTkzYWRmYzFjNyIsImlhdCI6MTc0ODM5NDYzNCwiZXhwIjoxNzQ4Mzk1NTM0fQ.B9MTar6QOnuuRnqtobOSLD4EAoQfERmwAxvkzwgekfw
-H "Content-Type: application/json"
-d '{ "password": "newSecurePassword123" }'

Note: Don’t put quotation for the token

You will get {"message":"Password reset successful"}

—------------------------------------------------

Checking Refresh First, login and get access and refresh tokens:

curl -X POST https://levichbackend.onrender.com/api/auth/login
-H "Content-Type: application/json"
-d '{"email":"your_email","password":"your_password"}'
-c cookies.txt

This saves cookies (including refreshToken) to cookies.txt. Then call refresh with saved cookies: curl -X POST https://levichbackend.onrender.com/api/auth/refresh
-b cookies.txt
-i

—----------------------------------------------------------------------------------------------------------------------------
