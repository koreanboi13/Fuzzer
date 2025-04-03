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

#define DRRUN_PATH "E:/labs/MBKS/lab_1/DynamoRIO-Windows-11.90.20133/bin32/drrun.exe"
#define MUTATION_LOG "mutation.txt"
#define MAIN_FOLDER_PATH  "E:/labs/MBKS/lab_1"
#define COVERAGE_FOLDER_PATH "E:/labs/MBKS/lab_1/coverage_log"

std::string vulnNum;
std::string VULN;
std::string CONFIG;
std::string DEFAULT_CONFIG;
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
void copyVulnFile() {

    fs::path exeSourcePath = fs::current_path() / "vulns" / VULN;

    fs::path configSourcePath = fs::current_path() / "vulns" / CONFIG;

  
    fs::path exeDestinationPath = fs::current_path() / VULN;
  
    fs::path configDestinationPath = fs::current_path() / CONFIG;
   
    std::string copyName = std::string("config_") + vulnNum + "_default";
    fs::path configCopyPath = fs::current_path() / copyName;

    try {
        if (!fs::exists(exeSourcePath)) {
            std::cerr << "Ошибка: файл " << exeSourcePath << " не найден!\n";
            return;
        }


        if (!fs::exists(configSourcePath)) {
            std::cerr << "Ошибка: файл " << configSourcePath << " не найден!\n";
            return;
        }

        fs::copy_file(exeSourcePath, exeDestinationPath, fs::copy_options::overwrite_existing);
        std::cout << "Файл " << VULN << " скопирован в " << exeDestinationPath << "\n";

        fs::copy_file(configSourcePath, configDestinationPath, fs::copy_options::overwrite_existing);
        std::cout << "Файл " << CONFIG << " скопирован в " << configDestinationPath << "\n";

        fs::copy_file(configDestinationPath, configCopyPath, fs::copy_options::overwrite_existing);
        std::cout << "Файл " << CONFIG << " скопирован как " << configCopyPath << "\n";

    } 
    catch (const fs::filesystem_error& e) {
        std::cerr << "Ошибка работы с файлами: " << e.what() << '\n';
    }
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
    int res = CopyFileA(DEFAULT_CONFIG.c_str(), CONFIG.c_str(), false);
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


void getRegistersState(CONTEXT* cont, const char* error, HANDLE hProcess, Mutation mut)
{
	unsigned char buffer[4048] = { 0 };
	SIZE_T recvSize = 0;

    std::fstream file("stack.log", std::ios::app);

    file << "Error: " << error << std::endl;
    file << "Filname: " << VULN << std::endl;
    file << "Mutation: " << std::endl; 
    file << "Type: ";
    switch(mut.type){
        case 0:
            file << "Replaced one byte" << std::endl;
            file << "Offset: " << mut.offset << std::endl;
            file << "Value: " << std::hex << mut.value << std::endl;
            break;
        case 1: 
            file << "Replaced multiple byte" << std::endl;
            file << "Offset: " << mut.offset << std::endl;
            file << "Value: " << std::hex << mut.value << std::endl;
            file << "Count: " << std::dec <<mut.count << std::endl;
            break;
        case 2:
            file << "Append to end of file" << std::endl;
            file << "Offset: " << mut.offset << std::endl;
            file << "Value: " << std::hex << mut.value << std::endl;
            file << "Count: " << std::dec << mut.count << std::endl;
            break;
    }

    file <<"eax  :  " << (void*)cont->Rax << "\n" <<  "esp  :  " << (void*)cont->Rsp << std::endl;
    file <<"ebx  :  " << (void*)cont->Rbx << "\n" <<  "ebp  :  " << (void*)cont->Rbp << std::endl;
    file <<"ecx  :  " << (void*)cont->Rcx << "\n" <<  "edi  :  " << (void*)cont->Rdi << std::endl;
    file <<"edx  :  " << (void*)cont->Rdx << "\n" <<  "esi  :  " << (void*)cont->Rsi << std::endl;
    file <<"eip  :  " << (void*)cont->Rip << "\n" <<  "flg  :  " << (void*)cont->EFlags << std::endl;
    ReadProcessMemory(hProcess, (void*)cont->Rsp, buffer, sizeof(buffer), &recvSize);

	if (recvSize != 0)
	{
		file << "\nStack (" << std::dec <<recvSize << " " <<  "bytes read)" << std::endl;

		for (int i = 0; i < recvSize; i++)
		{
			if ((i + 1) % 4 == 1)
			{
                file << (void*)((char*)cont->Rsp + i) << " :";
			}

			if (buffer[i] < 0x10)
			{
                file << "0";
			}

			
            file << std::hex << (int)buffer[i] << " ";

			if ((i + 1) % 4 == 0)
			{
				
                file << "\n";
			}
		}
	}

    file << "--------------------------------\n\n";
	memset(buffer, 0, sizeof(buffer));
	std::cout << "\nERROR! " << error << std::endl;
}

void runProgram(Mutation mut)
{
	PROCESS_INFORMATION pi;
	STARTUPINFOA si;
	DEBUG_EVENT debug_event = { 0 };
	HANDLE thread;
	CONTEXT cont;

	BOOL status;
    std::vector<char> vuln(VULN.begin(), VULN.end());
    vuln.push_back('\0');
	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	status = CreateProcessA(NULL, vuln.data(), NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi);
	if (status == false)
	{
		std::cout << "CreateProcess failed: " << std::dec << GetLastError() << std::endl;
		return;
	}

	while(1)
	{
		
		status = WaitForDebugEvent(&debug_event, 500);
		if (status == false)
		{
			if (GetLastError() != ERROR_SEM_TIMEOUT)
				std::cout << "WaitForDebugEvent failed: " << std::dec << GetLastError() << std::endl;
			break;
		}

		if (debug_event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT)
		{
			ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
			continue;
		}

		
		thread = OpenThread(THREAD_ALL_ACCESS, FALSE, debug_event.dwThreadId);
		if (thread == NULL)
		{
			std::cout << "OpenThread failed: " << std::dec << GetLastError() << std::endl;
			break;
		}

		cont.ContextFlags = CONTEXT_FULL;

		status = GetThreadContext(thread, &cont);
		if (status == false)
		{
			std::cout << "GetThreadContext failed: " << std::dec << GetLastError() << std::endl;
			CloseHandle(thread);
			break;
		}

		switch (debug_event.u.Exception.ExceptionRecord.ExceptionCode)
		{
		case EXCEPTION_ACCESS_VIOLATION:
			getRegistersState(&cont, "Access Violation", pi.hProcess, mut);
			break;
		case EXCEPTION_STACK_OVERFLOW:
			getRegistersState(&cont, "Stack overflow", pi.hProcess, mut);
			break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            getRegistersState(&cont, "Divide by zero", pi.hProcess, mut);
            break;
        case EXCEPTION_INT_OVERFLOW:
            getRegistersState(&cont, "Int overflow", pi.hProcess, mut);
            break;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            getRegistersState(&cont,"Array bounds exceeded", pi.hProcess, mut);
            break;
		default:
			std::cout << "Unknown exception: " << std::dec << debug_event.u.Exception.ExceptionRecord.ExceptionCode << std::endl;
			ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
		}
	}

	CloseHandle(pi.hProcess);
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
        if (line.find("vuln"+vulnNum+".exe") != std::string::npos ){
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
    int flag = 0;
    for (int i = 0; i < FUZZ_COUNT; i++) {
        if(!flag)
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
        runProgram(mutation);

        if (runWithDynamoRIO(coverageSet)) {
            successfulMutations.push_back(mutation); 
            stagnationCounter = 0;
            coverage << "[GOOD] Успешная мутация: type=" << type << ", offset=" << offset << ", value=" << std::hex << (int)value << ", count=" << std::dec << count << std::endl;
            saveSuccessfulMutations();
            flag = 1;
        } 
        else {
            stagnationCounter++;
            std::cerr << "Ошибка! Запись сбойного конфигурационного файла.\n";
            coverage << "[BAD] CODE COVER DOWN" << std::endl;
            flag = 0;
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
    std::cout << "8) Запустить программу" << std::endl;
    std::cout << "9) Поменять бинарник" << std::endl;
    std::cout << "0) Заверешение" << std::endl;
}
void chooseVuln(){
    std::cout << "Выберете номер бинарника: " << std::endl;
    std::cin >> vulnNum;
    CONFIG = "config_"+vulnNum;
    DEFAULT_CONFIG = "config_"+vulnNum+"_default";
    VULN = "vuln"+vulnNum+".exe";
    return;
}

int main() {
    chooseVuln();
    copyVulnFile();
    menu();
    int ans;
    int value;
    int offset,count;
    Mutation mut;
    memset(&mut, 0, sizeof(Mutation));
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
            case 8:
                runProgram(mut);
                break;
            case 9:
                chooseVuln();
                copyVulnFile();
                break;
        }
        menu();
    }
	return 0;
}
