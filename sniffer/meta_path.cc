#include "meta_path.h"



MetaPath::MetaPath(){

}

Path MetaPath::get_last(){
    return this->path.back();
}