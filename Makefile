build:
	zig build-exe src/main.zig -L/usr/share -lgpgme -lassuan -lgpg-error -lc -D_FILE_OFFSET_BITS=64
