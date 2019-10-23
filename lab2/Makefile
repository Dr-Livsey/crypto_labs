CXX		  	:= g++
CXX_FLAGS 	:= -Wall -Wextra -std=c++17 -ggdb -c

LD		  	:= ld

BIN_DIR		:= bin
SRC_DIR		:= src
OBJ_DIR 	:= obj

SRC			:= $(wildcard $(SRC_DIR)/*.cpp)
OBJ			:= $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o, $(SRC))
		

INCLUDE		:= include \
			   /home/boris/cpp_json/include \
			   ../lab1/include

LIB			:= lib \
			   ..

LIBRARIES	:= :libtext.a
			   
EXECUTABLE	:= main


all: $(OBJ_DIR) $(BIN_DIR) $(OBJ) $(BIN_DIR)/$(EXECUTABLE)

$(OBJ_DIR):
	@echo "Creating obj dir"
	@mkdir $(OBJ_DIR)

$(BIN_DIR):
	@echo "Creating exec dir"
	@mkdir $(BIN_DIR)

$(OBJ): $(OBJ_DIR)/%.o:  $(SRC_DIR)/%.cpp
	$(CXX) $(CXX_FLAGS) $(addprefix -I,$(INCLUDE)) $^ -o $@

$(BIN_DIR)/$(EXECUTABLE): $(OBJ)
	$(CXX) $(addprefix -L,$(LIB)) $^ -o $@ $(addprefix -l,$(LIBRARIES))

run: clean all
	clear
	@./$(BIN_DIR)/$(EXECUTABLE)

clean:
	-rm $(BIN_DIR)/*

cleanall: clean
	rm -rf $(OBJ_DIR)
