use strict;
use warnings;

use Test::Nginx::Socket;

# repeat_each(2);
plan tests => repeat_each() * 3 * blocks();

run_tests();

__DATA__

=== TEST 1: on
--- config
    location /on {
        default_type text/html;
        return 200 '<html><body>hello</body></html>';
        length_hiding on;
    }
--- request
GET /on
--- response_headers
Content-Type: text/html
--- response_body_like: ^<html><body>hello</body></html><!-- random-length HTML comment:

=== TEST 2: off
--- config
    location /off {
        default_type text/html;
        return 200 '<html><body>hello</body></html>';
        length_hiding off;
    }
--- request
GET /off
--- response_headers
Content-Type: text/html
--- response_body_unlike: <!-- random-length HTML comment:
