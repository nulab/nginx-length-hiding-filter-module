use strict;
use warnings;

use Test::Nginx::Socket;

# repeat_each(2);
plan tests => repeat_each() * 2 * blocks();

run_tests();

__DATA__

=== TEST 1: 204
--- config
    location /204 {
        default_type text/html;
        length_hiding on;
        return 204;
    }
--- request
GET /204
--- error_code: 204
--- response_body_unlike: <!-- random-length HTML comment:

=== TEST 2: 403
--- config
    location /403 {
        default_type text/html;
        return 403 '<html><body>Forbidden</body></html>';
        length_hiding on;
    }
--- request
GET /403
--- error_code: 403
--- response_body_like: ^<html><body>Forbidden</body></html><!-- random-length HTML comment:
