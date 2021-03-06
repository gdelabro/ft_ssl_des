NAME = ft_ssl

SRC_PATH = src
SRC_NAME =	main.c parsing.c hashing.c md5.c sha256.c utils.c hash_parse.c\
			cipher_parse.c base64.c base64_decode.c des_init.c des_alg.c\
			create_subkeys.c sha_funct.c

OBJ_PATH = obj
OBJ_NAME = $(SRC_NAME:.c=.o)

CC = gcc
CFLAGS = -Wall -Werror -Wextra

LIB = ft_printf/libftprintf.a

SRC = $(addprefix $(SRC_PATH)/,$(SR_NAME))
OBJ = $(addprefix $(OBJ_PATH)/,$(OBJ_NAME))

all: $(LIB) $(NAME)

$(LIB):
	@make -C ft_printf

$(NAME): $(OBJ)
	@printf "\n"
	@$(CC) $^ $(LIB) -o $@
	@echo "Compilation of \033[33;1m$(NAME)\033[0;1m: [\033[1;32mOK\033[0;1m]"

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c
	@printf "\033[34;1m| \033[0;1m"
	@mkdir $(OBJ_PATH) 2> /dev/null || true
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@make -C ft_printf clean
	@rm -f $(OBJ)
	@rm -rf $(OBJ_PATH)
	@echo "\033[33;1m$(NAME)\033[0;1m: objects deleted"

fclean: clean
	@make -C ft_printf fclean
	@rm -rf $(NAME)
	@echo "\033[33;1m$(NAME)\033[0;1m: $(NAME) deleted"

re: fclean all

.PHONY: all clean fclean re
