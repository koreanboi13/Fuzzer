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

std::vector<std::pair<int, uint8_t>> successfulMutations;


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
    file.write((const char*)(boundaries.data()), boundaries.size());
    file.close();
}

int parseCoverageLog(const std::string& filename) {
    std::ifstream file(filename);
    std::string line;
    int dllCount = 0;
    while (std::getline(file, line))
        if (line.find("module[  0]") != std::string::npos || line.find("module[  4]") != std::string::npos) 
            dllCount++;
    return dllCount;
}

bool runWithDynamoRIO(int& coverageSet) {
    std::fstream coverage("coverage_log.txt");
    std::string command = DRRUN_PATH;
    command += " -t drcov -dump_text -- ";
    command += VULN;

    system(command.c_str());
    coverage_log = fileName(MAIN_FOLDER_PATH);
    int newCoverage = parseCoverageLog(coverage_log);
    bool expanded = newCoverage > coverageSet;
    if(expanded){
        coverage << "[GOOD] CODE COVER UP! " << newCoverage << std::endl;
        coverageSet = newCoverage;
    }
    
    moveFile(coverage_log);
    return expanded;

}
void saveSuccessfulMutations() {
    std::ofstream file(MUTATION_LOG, std::ios::binary);
    for (const auto& mutation : successfulMutations) {
        file.write((const char*)(&mutation.first), sizeof(int));
        file.write((const char*)(&mutation.second), sizeof(uint8_t));
    }
}

void applySuccessfulMutations() {
    for (const auto& mutation : successfulMutations)
        replaceOneByte(mutation.first, mutation.second);
}
void fuzz() {
    std::fstream coverage("coverage_log.txt");
    srand(time(NULL));
    int maxOffset = fileSize(CONFIG);
    int maxValue = 255;
    int mutationType = 2;
    int stagnationCounter = 0;
    int maxCount = 100; 
    int coverageSet = 0;
    
    for(int i = 0; i < FUZZ_COUNT; i++) {
        returnDefault();
        
        if (stagnationCounter >= 100) {
            std::cout << "Возврат к лучшим мутациям" << std::endl;
            applySuccessfulMutations();
            stagnationCounter = 0;
        }

        int type = rand() % (mutationType+1);
        size_t offset = rand() % (maxOffset+1);
        uint8_t value = rand() % (maxValue+1);
        int count = rand() % (maxCount+1);
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
            successfulMutations.emplace_back(offset, value);
            stagnationCounter = 0;
            coverage << "[GOOD] Successfull mutation"<< std::endl; 
            saveSuccessfulMutations();
            continue;
        } 
        else {
            stagnationCounter++;
            std::cerr << "Ошибка! Запись сбойного конфигурационного файла.\n";
            coverage << "[BAD] CODE COVER DOWN" << std::endl;
            std::ofstream log("crash_input.txt", std::ios::binary);
            std::ifstream input(CONFIG, std::ios::binary);
            log << input.rdbuf();
            continue;
        }
    }
    std::cout << "[NEW]Новое покрытие: " << coverageSet << std::endl;
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

                appendToFile(value, offset);
                break;
            case 7:
                fuzz();
                break;   
        }
        menu();
    }
	return 0;
}
