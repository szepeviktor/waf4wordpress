<?php

// First command line argument
$pwd = $argv[1];
// Defaults to US layout
$psk = new Password_Strength_Keyboard();
$pos = $psk->weakness( $pwd );

if ( false === $pos ) {
    echo 'OK: ' . $pwd;
} else {
    echo substr_replace( $pwd, '<', $pos + 1, 0 );
}
echo "\n";
exit;


// Hungarian layout
$extras = array(
    "0" => array( 0, 1 ),
    "§" => array( 0, 1 ),
);
$map = array(
    array(
        1 => "123456789ÖÜÓ",
        2 => "qwertzuiopőú",
        3 => "asdfghjkléáű",
        4 => "yxcvbnm,.-",
    ),
    array(
        1 => "'\"+!%/=()ÖÜÓ",
        2 => "QWERTZUIOPŐÚ",
        3 => "ASDFGHJKLÉÁŰ",
        4 => "YXCVBNM?:_",
    ),
);
// First command line argument
$pwd = $argv[1];
$psk = new Password_Strength_Keyboard( $map, $extras );
$pos = $psk->weakness( $pwd );

if ( false === $pos ) {
    echo 'OK: ' . $pwd;
} else {
    echo substr_replace( $pwd, '<', $pos + 1, 0 );
}
echo "\n";
exit;


// Most used passwords
$pwds = '123456,password,12345678,qwerty,123456789,12345,1234,111111,1234567,dragon,123123,baseball,abc123,football,monkey,letmein,shadow,master,696969,mustang,666666,qwertyuiop,123321,1234567890,pussy,superman,654321,1qaz2wsx,7777777,fuckyou,qazwsx,jordan,123qwe,000000,killer,trustno1,hunter,harley,zxcvbnm,asdfgh,buster,batman,soccer,tigger,charlie,sunshine,iloveyou,fuckme,ranger,hockey,computer,starwars,asshole,pepper,klaster,112233,zxcvbn,freedom,princess,maggie,pass,ginger,11111111,131313,fuck,love,cheese,159753,summer,chelsea,dallas,biteme,matrix,yankees,6969,corvette,austin,access,thunder,merlin,secret,diamond,hello,hammer,fucker,1234qwer,silver,gfhjkm,internet,samantha,golfer,scooter,test,orange,cookie,q1w2e3r4t5,maverick,sparky,phoenix,mickey';
$psk = new Password_Strength_Keyboard();
foreach ( explode( ',', $pwds ) as $number => $pwd ) {
    $pos = $psk->weakness( $pwd );
    echo $number . '. ';

    if ( false === $pos ) {
        echo 'OK: ' . $pwd;
    } else {
        echo substr_replace( $pwd, '<', $pos + 1, 0 );
    }
    echo "\n";
}
exit;


class Password_Strength_Keyboard {

    /**
     * Coordinates of keys
     */
    private $coords = array(
        "`" => array( 0, 1 ),
        "~" => array( 0, 1 ),
    );

    /**
     * QWERTY keyboard map
     */
    private $map = array(
        array(
            1 => "1234567890-=",
            2 => "qwertyuiop[]\\",
            3 => "asdfghjkl;'",
            4 => "zxcvbnm,./",
        ),
        array(
            1 => "!@#$%^&*()_+",
            2 => "QWERTYUIOP{}|",
            3 => "ASDFGHJKL:\"",
            4 => "ZXCVBNM<>?",
        ),
    );

    public function __construct( $map = null, $extras = null ) {

        if ( is_array( $map ) ) {
            $this->map = $map;
        }
        if ( is_array( $extras ) ) {
            $this->coords = $extras;
        }

        // Loop through maps, rows and keys
        foreach ( $this->map as $rows ) {
            foreach ( $rows as $row_number => $row ) {
                $keys = $this->mb_str_split( $row );
                foreach ( $keys as $key_number => $key ) {
                    // Provide a mechanism to add incomplete rows
                    if ( ' ' === $key ) {
                        continue;
                    }
                    $this->coords[ $key ] = array( $key_number + 1, $row_number );
                }
            }
        }
    }

    /**
     * Detect consecutive keystrokes
     */
    public function weakness( $password ) {

        $chars = $this->mb_str_split( $password );
        // Previous 3 keys
        $last3 = array(
            array( -2, -2 ),
            array( -2, -2 ),
            array( -2, -2 ),
        );

        foreach ( $chars as $position => $key ) {
            if ( ! array_key_exists( $key, $this->coords ) ) {
                continue;
            }

            array_push( $last3, $this->coords[ $key ] );
            array_shift( $last3 );

            if ( $this->are_neighbors( $last3[0], $last3[1] )
                && $this->are_neighbors( $last3[1], $last3[2] )
            ) {
                return $position;
            }
        }

        // We are OK
        return false;
    }

    private function are_neighbors( $key1, $key2 ) {

        // Same position
        if ( $key1 === $key2 ) {
            return true;
        }

        // Horizontal neighbors
        if ( $key1[1] === $key2[1] && abs( $key1[0] - $key2[0] ) < 2 ) {
            return true;
        }

        // Vertical neighbors
        if ( $key1[0] === $key2[0] && abs( $key1[1] - $key2[1] ) < 2 ) {
            return true;
        }

        return false;
    }

    /**
     * Convert a multibyte string to an array
     *
     * @link http://php.net/manual/en/function.mb-split.php#92665
     */
    private function mb_str_split( $string ) {

        $stop = mb_strlen( $string );
        $result = array();

        for ( $idx = 0; $idx < $stop; $idx++ ) {
            $result[] = mb_substr( $string, $idx, 1 );
        }

        return $result;
    }
}
