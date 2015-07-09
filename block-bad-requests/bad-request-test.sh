#!/bin/bash
#
# Test all fail2ban triggers in O1_Bad_Request.
# Set all variables below. Stop the webserver and use `nc -l -p 80` to grab values.
# Test then COMMENT out "local access" check in O1_Bad_Request class.
#
# VERSION       :0.1
# DATE          :2014-08-16
# AUTHOR        :Viktor Szépe <viktor@szepe.net>
# LICENSE       :The MIT License (MIT)
# URL           :https://github.com/szepeviktor/wordpress-plugin-construction
# BASH-VERSION  :4.2+
# DEPENDS       :apt-get install netcat-traditional


HOST="subdir.wp"
PORT="80"
REQUEST="/sb/wp-login.php"
WP_ADMIN="/sb/wp-admin/"
USERNAME="viktor"
USERPASS="v12345"
PROTOCOL="HTTP/1.1"
UA="Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:24.7) Gecko/20140802 Firefox/24.7 PaleMoon/24.7.1"
ACCEPT="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
ACCEPT_LANG="hu,en-us;q=0.7,en;q=0.3"
ACCENT_ENC="gzip, deflate"
REFERER="http://${HOST}${REQUEST}"
COOKIE="wordpress_test_cookie=WP+Cookie+check"
CONNECTION="keep-alive"
CONTENT_TYPE="application/x-www-form-urlencoded"
CONTENT="log=${USERNAME}&pwd=${USERPASS}&wp-submit=Bejelentkez%C3%A9s&redirect_to=http%3A%2F%2F${HOST}%2Fsb%2Fwp-admin%2F&testcookie=1"
CONTENT_LENGTH="${#CONTENT}"

CR=$'\r'
# seconds to wait for the response from WordPress
RESPONSE_WAIT="1"
RESPONSE_TEMPLATE="^HTTP/1\.1 %s${CR}\$"
RESPONSE_COOKIE="^Set-Cookie: wordpress_.*; path=.*; httponly${CR}\$"
RESPONSE_LOC="^Location: http://${HOST}${WP_ADMIN}${CR}\$"

display_file() {
    local FILE="$1"

    if [ -s "$FILE" ]; then
        head -n 12 "$FILE"
    else
        echo "[empty file]"
    fi
}

check_response() {
    local FILE="$1"
    local HTTP_STATUS="$2"

    printf -v RESPONSE "$RESPONSE_TEMPLATE" "$HTTP_STATUS"

    #DEBUG echo -n "if ! grep -q $RESPONSE $FILE" | hexdump -C

    if ! grep -q "$RESPONSE" "$FILE"; then
        echo "invalid HTTP status code ($(display_file "$FILE"))" >&2
        return 1
    fi

    # return OK on other responses
    [ "$HTTP_STATUS" = "302 Found" ] || return 0

    if ! grep -q "$RESPONSE_LOC" "$FILE"; then
        echo "missing redirect to WP dashboard" >&2
        return 1
    fi

    if ! grep -q "$RESPONSE_COOKIE" "$FILE"; then
        echo "WP auth cookie not found" >&2
        return 1
    fi

    return 0
}

wp_login() {
    local NAME="$1"
    local HTTP_STATUS="$2"
    local FILE="$(tempfile)"
    local PID

    #( sleep $RESPONSE_WAIT; killall -9 nc &> /dev/null; ) &

    # fir Ipv6 use `nc6`
    nc.traditional -w $RESPONSE_WAIT $HOST $PORT > "$FILE"

    if check_response "$FILE" "$HTTP_STATUS"; then
        echo "OK: $NAME"
    else
        echo "FAILED: $NAME"
    fi

    echo

    rm "$FILE"
}


cat <<LOGIN | wp_login "login" "302 Found"
POST $REQUEST $PROTOCOL
Host: $HOST
User-Agent: $UA
Accept: $ACCEPT
Accept-Language: $ACCEPT_LANG
Accept-Encoding: $ACCENT_ENC
Referer: $REFERER
Cookie: $COOKIE
Connection: $CONNECTION
Content-Type: $CONTENT_TYPE
Content-Length: $CONTENT_LENGTH

$CONTENT
LOGIN


cat <<LOGIN | wp_login "author sniffing" "403 Forbidden"
GET /?author=2 $PROTOCOL
Host: $HOST
User-Agent: $UA
Accept: $ACCEPT
Accept-Language: $ACCEPT_LANG
Accept-Encoding: $ACCENT_ENC
Referer: $REFERER
Cookie: $COOKIE
Connection: $CONNECTION

LOGIN


cat <<LOGIN | wp_login "too big login request" "403 Forbidden"
POST $REQUEST $PROTOCOL
Host: $HOST
User-Agent: $UA
Accept: $ACCEPT
Accept-Language: $ACCEPT_LANG
Accept-Encoding: $ACCENT_ENC
Referer: $REFERER
Cookie: $COOKIE
Connection: $CONNECTION
Content-Type: $CONTENT_TYPE
Content-Length: $CONTENT_LENGTH
Too-Big: oShi6OxaeYiadie0euroo3biesheec8vod1kai1uV7Ohgh4cheegh1see2weiTeidaiFeehah8wie8oocohPaibaepha6Aen0Iegi1phu3oulii6tookieZ0chah1chias6tinginieBieziphahquie1AegoHoh9Zeeshi8ohquae1loGhoshie5cooje3aeju3toj6ieshaosoo2shahmaJieci1ieyuj6borohwooyei2yei5loeFivai5eirieGhu5shie1kee0aela0eifoa5ao3uux8OedoojiTeev8joh5ith7eesh9theiNgohlo8Shu1peetoh5eer9aDe3xeiKu1Zeis4thu3eiChah1aa7vah6oeng9mighio0veviecheiseebooJahn1pu6phoGhoLeedahb0pie8Ju1aoy1choquaishiepaichohch2hobugheel5caegh1IeY3Tee5moaweaCaozeeghieweez7eufu0phee8soosei7Zuquofahnoh4suzae1nitogh3kai7Yohah0theiraideeth2uthiek1shaikaHee5uiXu8aexa9fei7Eecai4EeJail3oV6eingae5oid5phaiph7pooBadoorea8che5peeYughiel0wooC1gochee7beeCejo5iucie3afohLohd8thaaPhae1Caisaeji8vaib3uone6ri3ieFei2yeem5uzoi5fuThee4ahbeejie3phoor1Ahb2Logh1Ragh7aechiew9UghoopakaeR5xoh1ievah1uaphaqueeSae4nacahbae0Eemeex2irohdaxe4pheil3mah7kah5eiPh3aethai1Jae8Iowee6iGoshai1ootaviecheesh7Etai2meu4uodohxae9UTahMouLoor1iegicaebeequei5viutathohXo9olooghie1ooCaph4ca9Aiseephiecah2cohfeiPheequeoG0daezoh4moo3eeMie0AiDai3iok0to5quae3ahZ0kaireg6yaesh4aequ2OhVoo5Hoo1shie8eeNgaeH8Oogh3Ohwoomakee1hoo8eeshaiqu6ua6oL3mex1yi0Ohn0ohl6loujeiFuo1Leb5Kie2eeY9kah5veehaen0Eex1Yie2jeip9moo0vou1yei8ej0Gapheib7oow4meatieGh2oozeitaSahb0vupei8eil2heikup6ahfiph6eitiethohp6eiJeiwoadu2iebaicoopae2yie9wa4eeth8ahr9taFee0upio8ye5ooZ1bohgohfe5ia9Cietoh2chexi5eip8aoPievacoongai2goochieweihoa0lie4IoX7Toowiw8APhaing1eep5aing4ool6aireeNg4Iezaepoh8UcauJu9hoi7Chahhah9qui6ohw5uul6ooWie2Ogho9veingae1tae8aig4ahGo4zaothaL1OBah3os3ohxaephaoma9chaequie6ameephokoh5EiQu0ut9aiCahh3mohb3queeniTohn5iesareek5xaemairoh2aew2Ui6Aechei5ohhahsap6yohjai2Matithe7ing0thitoh6moomaib9haeNgaithokeikiw8Aitogeegoiz9hieShighopheeriedeira8eiraing2pahyuphie3oaD4shae7aiphohpahseid0aeh6aW2ieziic4eiphu2Xiw6aisaing6Foo5mai2Ooqu3Mu9buuc7ohcai3cei2ig9iejie4ohDohshoh8oopien1asheet9shes8ungiequahfungaija1poof4shaihohchaa3IarieghaithiphinaiChai1shie9kaihoequ4aig1doofai1eePaetaeD9oCheiJ4DaethaiGhaiPh5joeHa7laizi1peiPh0iekei2eev8eeG2Vohqueivee

$CONTENT
LOGIN


cat <<LOGIN | wp_login "only POST requests to wp-login" "404 Not Found"
POST /sb/wp-trackback.php $PROTOCOL
Host: $HOST
User-Agent: $UA
Accept: $ACCEPT
Accept-Language: $ACCEPT_LANG
Accept-Encoding: $ACCENT_ENC
Referer: $REFERER
Cookie: $COOKIE
Connection: $CONNECTION
Content-Type: $CONTENT_TYPE
Content-Length: $CONTENT_LENGTH

$CONTENT
LOGIN


cat <<LOGIN | wp_login "banned usernames" "403 Forbidden"
POST $REQUEST $PROTOCOL
Host: $HOST
User-Agent: $UA
Accept: $ACCEPT
Accept-Language: $ACCEPT_LANG
Accept-Encoding: $ACCENT_ENC
Referer: $REFERER
Cookie: $COOKIE
Connection: $CONNECTION
Content-Type: $CONTENT_TYPE
Content-Length: 116

log=admin&pwd=$USERPASS&wp-submit=Bejelentkez%C3%A9s&redirect_to=http%3A%2F%2Fsubdir.wp%2Fsb%2Fwp-admin%2F&testcookie=1
LOGIN


cat <<LOGIN | wp_login "attackers use usernames with 'TwoCapitals'" "403 Forbidden"
POST $REQUEST $PROTOCOL
Host: $HOST
User-Agent: $UA
Accept: $ACCEPT
Accept-Language: $ACCEPT_LANG
Accept-Encoding: $ACCENT_ENC
Referer: $REFERER
Cookie: $COOKIE
Connection: $CONNECTION
Content-Type: $CONTENT_TYPE
Content-Length: 119

log=UserName&pwd=$USERPASS&wp-submit=Bejelentkez%C3%A9s&redirect_to=http%3A%2F%2Fsubdir.wp%2Fsb%2Fwp-admin%2F&testcookie=1
LOGIN


cat <<LOGIN | wp_login "accept header" "403 Forbidden"
POST $REQUEST $PROTOCOL
Host: $HOST
User-Agent: $UA
Accept: application
Accept-Language: $ACCEPT_LANG
Accept-Encoding: $ACCENT_ENC
Referer: $REFERER
Cookie: $COOKIE
Connection: $CONNECTION
Content-Type: $CONTENT_TYPE
Content-Length: $CONTENT_LENGTH

$CONTENT
LOGIN


cat <<LOGIN | wp_login "accept-language header" "403 Forbidden"
POST $REQUEST $PROTOCOL
Host: $HOST
User-Agent: $UA
Accept: $ACCEPT
Accept-Language: a
Accept-Encoding: $ACCENT_ENC
Referer: $REFERER
Cookie: $COOKIE
Connection: $CONNECTION
Content-Type: $CONTENT_TYPE
Content-Length: $CONTENT_LENGTH

$CONTENT
LOGIN


cat <<LOGIN | wp_login "content-type header" "403 Forbidden"
POST $REQUEST $PROTOCOL
Host: $HOST
User-Agent: $UA
Accept: $ACCEPT
Accept-Language: $ACCEPT_LANG
Accept-Encoding: $ACCENT_ENC
Referer: $REFERER
Cookie: $COOKIE
Connection: $CONNECTION
Content-Type: application/x-www-form
Content-Length: $CONTENT_LENGTH

$CONTENT
LOGIN


cat <<LOGIN | wp_login "content-length header" "400 Bad Request"
POST $REQUEST $PROTOCOL
Host: $HOST
User-Agent: $UA
Accept: $ACCEPT
Accept-Language: $ACCEPT_LANG
Accept-Encoding: $ACCENT_ENC
Referer: $REFERER
Cookie: $COOKIE
Connection: $CONNECTION
Content-Type: $CONTENT_TYPE

$CONTENT
LOGIN


cat <<LOGIN | wp_login "referer header" "403 Forbidden"
POST $REQUEST $PROTOCOL
Host: $HOST
User-Agent: $UA
Accept: $ACCEPT
Accept-Language: $ACCEPT_LANG
Accept-Encoding: $ACCENT_ENC
Referer: http://www.non.host${REQUEST}
Cookie: $COOKIE
Connection: $CONNECTION
Content-Type: $CONTENT_TYPE
Content-Length: $CONTENT_LENGTH

$CONTENT
LOGIN


cat <<LOGIN | wp_login "don't ban password protected posts (should FAIL)" "302 Found"
POST $REQUEST?action=postpass $PROTOCOL
Host: $HOST
User-Agent: $UA
Accept: $ACCEPT
Accept-Language: $ACCEPT_LANG
Accept-Encoding: $ACCENT_ENC
Referer: $REFERER
Cookie: $COOKIE
Connection: $CONNECTION
Content-Type: $CONTENT_TYPE
Content-Length: 39

post_password=1&Submit=K%C3%BCld%C3%A9s
LOGIN


cat <<LOGIN | wp_login "protocol version" "403 Forbidden"
POST $REQUEST HTTP/1.0
Host: $HOST
User-Agent: $UA
Accept: $ACCEPT
Accept-Language: $ACCEPT_LANG
Accept-Encoding: $ACCENT_ENC
Referer: $REFERER
Cookie: $COOKIE
Connection: $CONNECTION
Content-Type: $CONTENT_TYPE
Content-Length: $CONTENT_LENGTH

$CONTENT
LOGIN


cat <<LOGIN | wp_login "connection header" "403 Forbidden"
POST $REQUEST $PROTOCOL
Host: $HOST
User-Agent: $UA
Accept: $ACCEPT
Accept-Language: $ACCEPT_LANG
Accept-Encoding: $ACCENT_ENC
Referer: $REFERER
Cookie: $COOKIE
Connection: close
Content-Type: $CONTENT_TYPE
Content-Length: $CONTENT_LENGTH

$CONTENT
LOGIN


cat <<LOGIN | wp_login "accept-encoding header" "403 Forbidden"
POST $REQUEST $PROTOCOL
Host: $HOST
User-Agent: $UA
Accept: $ACCEPT
Accept-Language: $ACCEPT_LANG
Accept-Encoding: deflate
Referer: $REFERER
Cookie: $COOKIE
Connection: $CONNECTION
Content-Type: $CONTENT_TYPE
Content-Length: $CONTENT_LENGTH

$CONTENT
LOGIN


cat <<LOGIN | wp_login "cookie" "403 Forbidden"
POST $REQUEST $PROTOCOL
Host: $HOST
User-Agent: $UA
Accept: $ACCEPT
Accept-Language: $ACCEPT_LANG
Accept-Encoding: $ACCENT_ENC
Referer: $REFERER
Cookie: not-ok=value
Connection: $CONNECTION
Content-Type: $CONTENT_TYPE
Content-Length: $CONTENT_LENGTH

$CONTENT
LOGIN


cat <<LOGIN | wp_login "empty user agent" "403 Forbidden"
POST $REQUEST $PROTOCOL
Host: $HOST
Accept: $ACCEPT
Accept-Language: $ACCEPT_LANG
Accept-Encoding: $ACCENT_ENC
Referer: $REFERER
Cookie: $COOKIE
Connection: $CONNECTION
Content-Type: $CONTENT_TYPE
Content-Length: $CONTENT_LENGTH

$CONTENT
LOGIN


cat <<LOGIN | wp_login "botnets" "403 Forbidden"
POST $REQUEST $PROTOCOL
Host: $HOST
User-Agent: xy crawler
Accept: $ACCEPT
Accept-Language: $ACCEPT_LANG
Accept-Encoding: $ACCENT_ENC
Referer: $REFERER
Cookie: $COOKIE
Connection: $CONNECTION
Content-Type: $CONTENT_TYPE
Content-Length: $CONTENT_LENGTH

$CONTENT
LOGIN


cat <<LOGIN | wp_login "modern browsers" "403 Forbidden"
POST $REQUEST $PROTOCOL
Host: $HOST
User-Agent: Mozilla/4.0 (Windows NT 6.1; Win64; x64; rv:24.7) Gecko/20140802 Firefox/0.7
Accept: $ACCEPT
Accept-Language: $ACCEPT_LANG
Accept-Encoding: $ACCENT_ENC
Referer: $REFERER
Cookie: $COOKIE
Connection: $CONNECTION
Content-Type: $CONTENT_TYPE
Content-Length: $CONTENT_LENGTH

$CONTENT
LOGIN

