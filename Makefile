BUILD_DIR := build/

#--------------------------------------------------------------------------------------------------------------------------------

all: | $(BUILD_DIR)
	nasm -f elf64 main.s -o $(BUILD_DIR)main.o -l $(BUILD_DIR)main.lst
	gcc -no-pie $(BUILD_DIR)main.o -o $(BUILD_DIR)main

$(BUILD_DIR):
	mkdir -p $@

.PHONY: run
run:
	@./$(BUILD_DIR)main

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
