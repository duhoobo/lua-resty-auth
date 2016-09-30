http://www.networkinghowtos.com/howto/adding-users-to-a-htpasswd-file-for-nginx/


* crypt:

        printf "testuser:$(openssl passwd -crypt Pass123)\n" >> .htpasswd 

* apr1:

        printf "testuser:$(openssl passwd -apr1 Pass123)\n" >> .htpasswd 

* MD5

        printf "testuser:$(openssl passwd -1 Pass123)\n" >> .htpasswd 

* SSHA

        (USERNAME="testuser";PWD="Pass123";SALT="$(openssl rand -base64 3)"; \
         SHA1=$(printf "$PWD$SALT" | openssl dgst -binary -sha1 | \
         sed 's#$#'"$SALT"'#' | base64); \
         printf "$USERNAME:{SSHA}$SHA1\n" >> .htpasswd)

