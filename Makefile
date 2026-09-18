.PHONY: build test fmt lint check examples examples-asan demo

build:
	cargo build

test:
	cargo test

fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings

check: fmt lint test

examples:
	@mkdir -p target/examples
	cc -std=c11 -Wall -Wextra -O0 examples/vulnerable-programs/segfault.c -o target/examples/segfault
	cc -std=c11 -Wall -Wextra -O0 examples/vulnerable-programs/abort.c -o target/examples/abort
	cc -std=c11 -Wall -Wextra -O0 examples/vulnerable-programs/buffer_overflow.c -o target/examples/buffer_overflow
	cc -std=c11 -Wall -Wextra -O0 examples/vulnerable-programs/use_after_free.c -o target/examples/use_after_free

examples-asan:
	@mkdir -p target/examples-asan
	cc -std=c11 -Wall -Wextra -O0 -fsanitize=address -fno-omit-frame-pointer -g examples/vulnerable-programs/buffer_overflow.c -o target/examples-asan/buffer_overflow
	cc -std=c11 -Wall -Wextra -O0 -fsanitize=address -fno-omit-frame-pointer -g examples/vulnerable-programs/use_after_free.c -o target/examples-asan/use_after_free

demo: build examples
	target/debug/crashforge run target/examples/segfault examples/vulnerable-programs/inputs/segfault.txt
