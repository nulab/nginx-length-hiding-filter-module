use strict;
use warnings;

use Test::Nginx::Socket;

# repeat_each(2);
plan tests => repeat_each() * 2 * blocks();

run_tests();

__DATA__

=== TEST 1: application/json
--- config
    location /json {
        length_hiding on;
        default_type application/json;
        return 200 '{"test":"ok"}';
    }
--- request
GET /json
--- error_code: 200
--- response_body: {"test":"ok"}

=== TEST 2: text/plan
--- config
    location /json {
        length_hiding on;
        default_type text/plan;
        return 200 'Hello World';
    }
--- request
GET /json
--- error_code: 200
--- response_body: Hello World
