
# Nginx Length Hiding Filter Module

## Introduction

In [BREACH site](http://breachattack.com/), the mitigrations against BREACH attack are given as follows:

1. Disabling HTTP compression
2. Separating secrets from user input
3. Randomizing secrets per request
4. Masking secrets (effectively randomizing by XORing with a random secret per request)
5. Protecting vulnerable pages with CSRF
6. Length hiding (by adding random number of bytes to the responses)
7. Rate-limiting the requests

BREACH relys on HTTP compression and it's reasonable to disable it to secure your website. However without compresseion, some websites may meet severe performance degression or the cost may increase if you're charged based on the volume of traffic like AWS. In such case it may be difficult to turn off HTML compression for whole responses from your website and need to adopt other proper ways.

Other mitigrations listed from the 2nd to 5th above are basically applicable to your application but the 6th one, Length hiding, can be done on nginx. This filter module provides functionality to append randomly generated HTML comment to the end of response body to hide correct response length and make it difficult for attackers to guess secure token.

The sample of randomly appended HTML comment is here.
```
<!-- random-length HTML comment: JnSLGWeWYWsoJ4dXS3ubLw3YOu3zfGTotlzx7UJUo26xuXICQ2cbpVy1Dprgv8Icj6QfOZx2Ptp9HxCVoevTxhKzMzV6xeYXao0oCngRWJRb4Tvive1iBAXLzrHlLg6jKwNKXrct0tJuA2TvWIRVIng6UoffIbCQLPbi63PwmWemOxVi6m3CPa6hCbAK2CaBR1jLux7UJa4WNN4H0yIDMElMglWWouY5m5FUqAn0afMmtErj0zkA2LMWxisZRES38XLoYycySmaBrIih5IixUsJFR0ei4uZ0IifgV5SnitoNzMusSQem9npObHuU2HKApneAjwnFdPSQZA9sRdSOE8agDI05P832mV1JIcOjsg0FgzxvSG7UEX0HdqBqp2jPOYYW0k5gGtmkiXWydRJfn9lGomxReUeqq2Aec69gplEM6a8aqH5TFgXrGK8jcaPISQlsKkMxJQ7Fp6fVDbmI59xCIvlk -->
```
For every response, length of the random strings will vary within a given range.

This idea originally came from [breach-mitigation-rails](https://github.com/meldium/breach-mitigation-rails/). Thanks team!

## Warning

As said in breach-migration-rails, BREACH is complicated and wide-ranging attack and this module provides only PARTIAL protection. To secure your website or service wholly, you need to review BREACH paper and find proper way according to your own website or service.

## Installation

This filter module is tested with nginx 1.2.9 and nginx 1.4.2.

Download nginx sources from [http://nginx.org](http://nginx.org) and unpack it.

Run configure script with adding --add-module option with the directory where this module is extracted like this:
```
./configure --add-module=/path/to/nginx-length-hiding-filter-module
```
Of course, you can add other options here. Then build and install.
```
make
sudo make install
```

## Configuration Directives


### length_hiding

* syntax: length_hiding on | off
* default: off
* context: http, server, location, if in location

Enables or disables adding random generated HTML comment.

### length_hiding_max 

* syntax: length_hiding_max size
* default: 2048
* context: http, server, location

Sets maximum length of random generated string used in HTML comment. The size should be within a range from 256 and 2048.

## Example Configuration

Enable this module for specific location ('/hiding'). In this example, the length of random strings will be less than 1024.
```
server {
    listen       443 default_server deferred ssl spdy;
    server_name  example.com;
    length_hiding_max 1024;

    location /hiding {
        length_hiding on;
    }
}
```

