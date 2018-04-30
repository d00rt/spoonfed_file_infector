default:
	nasm -fwin32 spoonfed.asm
	ld -T spoonfed.ld spoonfed.obj -o spoonfed-v1.exe
	python patch.py