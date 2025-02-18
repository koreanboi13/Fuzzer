#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <windows.h>
#include <set>
#include <random>
#include <string>
#include <ctime>
#include <stdio.h>
#include <cstdlib>
#include <filesystem> 
#include <sys/stat.h>
#include <sstream>

#define FUZZ_COUNT 300

#define CONFIG "config_5"
#define DEFAULT_CONFIG "config_5_default"
#define VULN "vuln5.exe"
#define DRRUN_PATH "E:/labs/MBKS/lab_1/DynamoRIO-Windows-11.90.20133/bin32/drrun.exe"
#define MUTATION_LOG "mutation.txt"
#define MAIN_FOLDER_PATH  "E:/labs/MBKS/lab_1"
#define COVERAGE_FOLDER_PATH "E:/labs/MBKS/lab_1/coverage_log"


namespace fs = std::filesystem;
std::string coverage_log;

struct Mutation{
    int type;
    int offset;
    uint8_t value;
    int count;
};


std::vector<Mutation> successfulMutations;

std::string fileName(const std::string& folderPath) {
    std::string latestFile;
    std::filesystem::file_time_type latestTime;

    for (const auto& entry : fs::directory_iterator(folderPath)) {
        auto lastWriteTime = fs::last_write_time(entry);
        if (latestFile.empty() || lastWriteTime > latestTime) {
            latestFile = entry.path().filename().string();
            latestTime = lastWriteTime;
        }
    }
    return latestFile;
}

void moveFile(const std::string& filename) {
    std::string command = "mv " + filename + " " + COVERAGE_FOLDER_PATH ;
    std::cout << "command: " << command << std::endl;
    system(command.c_str());
    std::cout << filename << " перемещен в " << COVERAGE_FOLDER_PATH << std::endl; 
}


int fileSize(const std::string&filename){
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Ошибка открытия файла!" << std::endl;
        return 0;
    }

    file.seekg(0, std::ios::end);
    int fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    file.close();
    return fileSize;
}

void printFileBytes() {
    std::ifstream file(CONFIG, std::ios::binary);
    if (!file) {
        std::cerr << "Ошибка открытия файла!" << std::endl;
        return;
    }

    int size = fileSize(CONFIG);
    
    std::cout << "Размер файла: " << size << " байт" << std::endl;
    std::cout << "Содержимое файла (в байтах):" << std::endl;
    
    unsigned char byte;
    int count = 0;
    while (file.read((char*)(&byte), 1)) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') <<(unsigned)(byte) << " ";
        if (++count % 16 == 0) std::cout << "\n";
    }
    std::cout <<"\n";
    file.close();
}

void returnDefault(){
    int res = CopyFileA(DEFAULT_CONFIG, CONFIG, false);
	if (!res)
		std::cerr << "CopyFileA failed: " << std::dec << GetLastError() << std::endl;
}

void replaceOneByte(int offset, uint8_t value) {
    std::fstream file(CONFIG, std::ios::binary | std::ios::in | std::ios::out);
    if (!file) {
        std::cerr << "Ошибка открытия файла!" << std::endl;
        return;
    }
    file.seekp(offset);
    file.put((char)(value));
    file.close();
}

void replaceBytes(int offset, int count, uint8_t value) {
    std::fstream file(CONFIG, std::ios::binary | std::ios::in | std::ios::out);
    if (!file) {
        std::cerr << "Ошибка открытия файла!" << std::endl;
        return;
    }
    file.seekp(offset);
    for(int i = 0 ; i < count; i++)
		file.put(value);
    file.close();
}

void appendToFile(uint8_t value, int count) {
    std::fstream file(CONFIG, std::ios::binary | std::ios::app);
    if (!file) {
        std::cerr << "Ошибка открытия файла!" << std::endl;
        return;
    }
	file.seekp(0, std::ios::end);
    for(int i = 0 ; i < count; i++)
		file.put(value);
    file.close();
}

void replaceWithBoundaryValues(int offset) {
    const std::vector<unsigned int> boundaries = {0x00, 0xFF, 0xFF / 2, 0xFF / 2 - 1, 0xFF / 2 + 1, 0x0000, 0xFFFF, 0xFFFF / 2, 0xFFFF / 2 - 1, 0xFFFF / 2 + 1, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF / 2, 0xFFFFFFFF / 2 - 1, 0xFFFFFFFF / 2 + 1};
    std::fstream file(CONFIG, std::ios::binary | std::ios::in | std::ios::out);
    if (!file) {
        std::cerr << "Ошибка открытия файла!" << std::endl;
        return;
    }
    file.seekp(offset);
    file.write((const char*)(boundaries.data()), boundaries.size() * sizeof(unsigned int));
    file.close();
}

std::set<uintptr_t> parseCoverageLog(const std::string& filename) {
    std::ifstream file(filename);
    std::string line;
    std::set<uintptr_t> addresses;
    std::string vulnID;
    std::string dllID;
    
    std::string moduleStr;
    int moduleId;
    uintptr_t start;
    char comma;
    while (std::getline(file, line)) {
        if (line.find("vuln5.exe") != std::string::npos ){
            vulnID = line[2];
        }
        else if(line.find("func.dll") != std::string::npos){
            dllID = line[2];
        }
        if(line.find("module[  "+vulnID+"]") != std::string::npos || line.find("module[  "+dllID+"]") != std::string::npos  ){
            size_t colonPos = line.find(':');
            size_t commaPos = line.find(',');

            uintptr_t start = std::stoul(line.substr(colonPos + 2, commaPos - (colonPos + 2)), nullptr, 16);

            addresses.insert(start);
        }
    }
    return addresses;
}

bool runWithDynamoRIO(std::set<uintptr_t>& coverageSet) {

    std::ofstream coverage("coverage_log.txt", std::ios::app);
    if (!coverage) {
        std::cerr << "Ошибка открытия файла coverage_log.txt!" << std::endl;
        return false;
    }

    std::string command = DRRUN_PATH;
    command += " -t drcov -dump_text -- ";
    command += VULN;
    system(command.c_str());

    coverage_log = fileName(MAIN_FOLDER_PATH);

    std::set<uintptr_t> newCoverage = parseCoverageLog(coverage_log);

    if (newCoverage.size() > coverageSet.size()) {
        std::cout << "[GOOD] CODE COVER UP! " << newCoverage.size() << std::endl; 
        coverage << "[GOOD] CODE COVER UP! " << newCoverage.size() << std::endl; 
        coverageSet = newCoverage; 
        moveFile(coverage_log); 
        return true;
    } 
    else {
        coverage << "[BAD] CODE COVER DOWN " << newCoverage.size() << std::endl; 
        moveFile(coverage_log); 
        return false;
    }
}

void saveSuccessfulMutations() {
    std::ofstream file(MUTATION_LOG, std::ios::binary);
    if (!file) {
        std::cerr << "Ошибка открытия файла для сохранения мутаций!" << std::endl;
        return;
    }

    for (const auto& mutation : successfulMutations)
        file.write((const char*)(&mutation), sizeof(Mutation));
}

void applySuccessfulMutations() {
    for (const auto& mutation : successfulMutations) {
        switch (mutation.type) {
            case 0:
                replaceOneByte(mutation.offset, mutation.value);
                break;
            case 1:
                replaceBytes(mutation.offset, mutation.count, mutation.value);
                break;
            case 2:
                appendToFile(mutation.value, mutation.count);
                break;
            default:
                std::cerr << "Неизвестный тип мутации: " << mutation.type << std::endl;
                break;
        }
    }
}

void fuzz() {
    std::ofstream coverage("coverage_log.txt", std::ios::app);
    if (!coverage) {
        std::cerr << "Ошибка открытия файла coverage_log.txt!" << std::endl;
        return;
    }

    srand(time(NULL));
    int maxOffset = fileSize(CONFIG);
    int maxValue = 255;
    int mutationType = 2;
    int stagnationCounter = 0;
    int maxCount = 10000;
    std::set<uintptr_t> coverageSet;

    for (int i = 0; i < FUZZ_COUNT; i++) {
        returnDefault();

        if (stagnationCounter >= 100) {
            std::cout << "Возврат к лучшим мутациям" << std::endl;
            coverage << "[NEW] Возврат к лучшим мутациям" << std::endl;
            applySuccessfulMutations();
            stagnationCounter = 0;
        }

        int type = rand() % (mutationType + 1);
        size_t offset = rand() % (maxOffset + 1);
        uint8_t value = rand() % (maxValue + 1);
        int count = rand() % (maxCount + 1);

        Mutation mutation;
        mutation.type = type;
        mutation.offset = offset;
        mutation.value = value;
        mutation.count = count;

        switch (type) {
            case 0:
                replaceOneByte(offset, value);
                break;
            case 1:
                replaceBytes(offset, count, value);
                break;
            case 2:
                appendToFile(value, count);
                maxOffset = fileSize(CONFIG);
                break;
        }

        if (runWithDynamoRIO(coverageSet)) {
            successfulMutations.push_back(mutation); 
            stagnationCounter = 0;
            coverage << "[GOOD] Успешная мутация: type=" << type << ", offset=" << offset << ", value=" << std::hex << (int)value << ", count=" << std::dec << count << std::endl;
            saveSuccessfulMutations();
        } 
        else {
            stagnationCounter++;
            std::cerr << "Ошибка! Запись сбойного конфигурационного файла.\n";
            coverage << "[BAD] CODE COVER DOWN" << std::endl;
            std::ofstream log("crash_input.txt", std::ios::binary);
            std::ifstream input(CONFIG, std::ios::binary);
            log << input.rdbuf();
        }
    }
    std::cout << "[NEW] Новое покрытие: " << coverageSet.size() << std::endl;
}

void menu(){
	std::cout << "1) Вывести конфиг" << std::endl;
    std::cout << "2) Вернуть изначальный конфиг" << std::endl;
	std::cout << "3) Заменить один байт" << std::endl;
	std::cout << "4) Заменить несколько байт" << std::endl;
	std::cout << "5) Заменить байты на граничные значения" << std::endl;
	std::cout << "6) Дописать байты в конец" << std::endl;
    std::cout << "7) Автоматический фаззинг" << std::endl;
    std::cout << "0) Заверешение" << std::endl;
}

int main() {
    menu();
    int ans;
    int value;
    int offset,count;
    
    while(true)
    {
        std::cin >>  ans;
        switch(ans)
        {
            case 0:
                return 0;
            case 1:
                printFileBytes(); 
                break;
            case 2:
                returnDefault();
                break;
            case 3:
                std::cout << "Введите смещение: ";
                std::cin >> offset;
                std::cout << "\n";

                std::cout << "Введите значение: ";
                std::cin >> std::hex >> value;
                std::cout << "\n";

                replaceOneByte(offset, value);
                break;
            case 4:
                std::cout << "Введите смещение: ";
                std::cin >> offset;
                std::cout << "\n";

                std::cout << "Введите количество: ";
                std::cin >> count;
                std::cout << "\n";
            

                std::cout << "Введите значение: ";
                std::cin >> std::hex >> value;
                std::cout << "\n";
                
                replaceBytes(offset,count,value);
                break;
            case 5:
                std::cout << "Введите смещение: ";
                std::cin >> offset;
                std::cout << "\n";
                
                replaceWithBoundaryValues(offset);
                break;
            case 6:
                std::cout << "Введите количество: ";
                std::cin >> count;
                std::cout << "\n";

                std::cout << "Введите значение: ";
                std::cin >> std::hex >> value;
                std::cout << "\n";

                appendToFile(value, count);
                break;
            case 7:
                fuzz();
                break;   
        }
        menu();
    }
	return 0;
}
