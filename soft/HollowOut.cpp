#include "header/process.h"

#include <iostream>

std::string logo{
R"(
    
     __  __     ______     __         __         ______     __     __     ______     __  __     ______  
    /\ \_\ \   /\  __ \   /\ \       /\ \       /\  __ \   /\ \  _ \ \   /\  __ \   /\ \/\ \   /\__  _\ 
    \ \  __ \  \ \ \/\ \  \ \ \____  \ \ \____  \ \ \/\ \  \ \ \/ ".\ \  \ \ \/\ \  \ \ \_\ \  \/_/\ \/ 
     \ \_\ \_\  \ \_____\  \ \_____\  \ \_____\  \ \_____\  \ \__/".~\_\  \ \_____\  \ \_____\    \ \_\ 
      \/_/\/_/   \/_____/   \/_____/   \/_____/   \/_____/   \/_/   \/_/   \/_____/   \/_____/     \/_/ 
                                                                                                    
                                  Welcome to the HollowOut interface!
                 Host: The process to host the hider inside of. This process may become unresponsive.
                    Hider: The process that will hide inside of the host and appear as the host.
)"
};

int main()
{
    std::wstring host;
    std::wstring hider;

    std::string temp;
    bool confirmed{};

    do
    {
        std::cout << logo;

        std::cout << "\n\n      Enter Host: ";
        std::wcin >> host;

        std::cout << "\nEnter Hider: ";
        std::wcin >> hider;

        std::wcout << "\nYou entered: \nHost: " << host << "\nHider: " << hider << "\nIs this correct? (Y/n): ";
        std::cin >> temp;

        if (temp == "" || temp == "Y" || temp == "y")
            confirmed = true;

    } while (!confirmed);

    // Get the process id's from the user input.
    DWORD host_process_id = process::get_process_id(host);
    DWORD hider_process_id = process::get_process_id(hider);

    // Hollow the host and hide the hider from given process ids.
    process::hollow_process(host_process_id, hider_process_id);

    // Halt execution until user input closes the program.
    std::cin.get();
    return 0;
}