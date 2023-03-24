main: main.o
	gcc -no-pie $< -o $@

main.o: main.s my_printf.s
	nasm -f elf64 $< -l main.lst

my_printf.o: my_printf.s
	nasm -f elf64 $< -l my_printf.lst