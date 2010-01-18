// Password encryption
// Adapted from Apache's htpasswd 1.3 source code
// François Pirsch, 2003
//   documentation :
//     http://httpd.apache.org/docs/programs/htpasswd.html
//
//   source :
//     http://apache.dev.wapme.net/doxygen-1.3/htpasswd_8c-source.html
//     http://apache.dev.wapme.net/doxygen-1.3/ap__md5c_8c-source.html
//     http://apache.dev.wapme.net/doxygen-1.3/ap__sha1_8c-source.html

var ALG_PLAIN = 0;           // mot de passe en clair : ne fonctionnera pas sur les serveurs Unix
var ALG_CRYPT = 1;           // chiffrement par la fonction crypt() d'Unix
var ALG_APMD5 = 2;           // chiffrement en MD5, utilisé par défaut sous Windows entre autres.
var ALG_APSHA = 3;           // chiffrement en SHA-1
var AP_SHA1PW_ID = "{SHA}";
var AP_MD5PW_ID  = "$apr1$";

// Convertit en sorte de base-64 le nombre v, sur n caractères. Fonction dérivée du code d'Apache 1.3
var itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";  /* 0 ... 63 => ASCII - 64 */
function ap_to64(v, n) {
  var s = '';
  while (--n >= 0) {
    s += itoa64.charAt(v&0x3f);  // prend les 6 bits les plus à droite.
    v >>>= 6;                    // décale de 6 bits.
  }
  return s;
}

// Convertit une chaîne en tableau de codes ASCII.
function stringToArray(s) {
  var a=[];
  for (var i = 0; i < s.length; i++) a.push(s.charCodeAt(i));
  return a;
}

function htpasswd(user, pw, alg) {
/*
  if (!user || !pw) {
    alert('Il faut un nom d\'utilisateur et un mot de passe.');
    return '';
  }
*/
  // un peu de sel pour mettre dans les mots de passe en MD5 ou Crypt : 8 caractères aléatoires en base 64.
  // On fait 4 + 4, parce que 8 caractères c'est trop pour être stocké dans un entier.
  var salt = ap_to64(Math.floor(Math.random()*16777215), 4)    // 2^24-1 : 4 * 6 bits.
           + ap_to64(Math.floor(Math.random()*16777215), 4);   // 2^24-1 : 4 * 6 bits.


  var plus127 = 0;
  for (var i=0; i<user.length; i++) if (user.charCodeAt(i) > 127) plus127++;
  if (plus127) alert("Apache doesn't like non-ascii characters in the user name.");

  var cpw  = '';         // Mot de passe chiffré ; max 119 caractères.
  switch (alg) {
    /*
     * output of base64 encoded SHA1 is always 28 chars + AP_SHA1PW_ID length (ce qui fait 33 caractères)
     */
    case ALG_APSHA:
      cpw = AP_SHA1PW_ID + b64_sha1(pw);
      break;

    case ALG_APMD5:
      var msg = pw;          // On commence par le mot de passe en clair
      msg += AP_MD5PW_ID;    // puis le petit mot magique
      msg += salt;           // et un peu de sel.
      /*
       * Then just as many characters of the MD5(pw, salt, pw)
       */
      var final_ = str_md5(pw + salt + pw);
      for (var pl = pw.length; pl > 0; pl -= 16) msg += final_.substr(0, (pl > 16) ? 16 : pl);

      /*
       * Then something really weird...
       */
      for (i = pw.length; i != 0; i >>= 1)
        if (i & 1) msg += String.fromCharCode(0);
        else msg += pw.charAt(0);
      final_ = str_md5(msg);

      /*
       * Ensuite une partie pour ralenir les choses ! En JavaScript ça va être vraiment lent !
       */
      var msg2;
      for (i = 0; i < 1000; i++) {
        msg2 = '';
        if (i & 1) msg2 += pw; else msg2 += final_.substr(0, 16);
        if (i % 3) msg2 += salt;
        if (i % 7) msg2 += pw;
        if (i & 1) msg2 += final_.substr(0, 16); else msg2 += pw;
        final_ = str_md5(msg2);
      }
      final_ = stringToArray(final_);

      /*
       * Now make the output string.
       */
      cpw = AP_MD5PW_ID + salt + '$';
      cpw += ap_to64((final_[ 0]<<16) | (final_[ 6]<<8) | final_[12], 4);
      cpw += ap_to64((final_[ 1]<<16) | (final_[ 7]<<8) | final_[13], 4);
      cpw += ap_to64((final_[ 2]<<16) | (final_[ 8]<<8) | final_[14], 4);
      cpw += ap_to64((final_[ 3]<<16) | (final_[ 9]<<8) | final_[15], 4);
      cpw += ap_to64((final_[ 4]<<16) | (final_[10]<<8) | final_[ 5], 4);
      cpw += ap_to64(                    final_[11]               , 2);
      break;

    case ALG_PLAIN:
      cpw = pw;
      break;

    case ALG_CRYPT:
    default:
      cpw = Javacrypt.displayPassword(pw, salt);
      break;
  }

  /*
   * Check to see if the buffer is large enough to hold the username,
   * hash, and delimiters.
   */
  if (user.length + 1 + cpw.length > 255) alert('Your login and password are too long.');
  else return user + ':' + cpw;
}

//=========================================
// Génération d'un mot de passe
//=========================================
function pwgen(pwl) {
  // On peut mettre d'autres caractères, y compris des lettres accentuées (encore faut-il que
  // le code ASCII soit le même sur les 3 systèmes codeur, client et serveur)
  // Mais on gagne nettement plus en augmentant la taille du mot de passe que le nombre de caractères.
  var source = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-#$@+_()[]{}=%*!§";
  var pw = '';
  for (var i = 1; i <= pwl; i++) {
    pw += source.substr(Math.floor(Math.random()*source.length),1);
  }
  return pw;
}

function generate_htpasswd() {
  var username = $('username').value;
  var password = $('password').value;
  
  var crypted = htpasswd(username, password, ALG_CRYPT);
  
  $('htpasswd_label').innerHTML = 'Ergebnis:';
  $('htpasswd_content').innerHTML = crypted;
}