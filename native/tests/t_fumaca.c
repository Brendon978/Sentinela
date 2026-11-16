#include <string.h>

#include "sentinela.h"
#include "teste.h"

TESTE(fumaca_versao) {
    CONFERE(strcmp(sn_versao(), "0.1.0") == 0);
}
