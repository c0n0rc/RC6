PROJECT= rc6

CC= g++
FLAGS= -ansi -o

C_FILES= rc6.cpp
O_FILES= rc6.o 

run:	$(C_FILES) $(H_FILES)
		$(CC) $(FLAGS) run $(C_FILES)

run_it:	run
		./run

clean:	
		rm -f run.o 
		rm -f run