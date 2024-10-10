using System.Collections.Concurrent;                    // Додає підтримку для колекцій, які забезпечують
                                                        // безпечний доступ з кількох потоків (наприклад, ConcurrentQueue) 

using System.Runtime.InteropServices;                   // Додає підтримку для роботи з неуправляємими ресурсами та
                                                        // викликами функцій Windows API (P/Invoke)

class Program
{
    // Константи для VirtualAlloc  
    private const uint MEM_RESERVE = 0x2000;            // Параметр для резервування регіону пам'яті  
    private const uint MEM_COMMIT = 0x1000;             // Параметр для комітування (активації) регіону пам'яті  
    private const uint PAGE_NOACCESS = 0x01;            // Пам'ять не може бути доступною (неможливий доступ для читання/запису)  
    private const uint PAGE_READWRITE = 0x04;           // Пам'ять доступна для читання та запису


    // Константи для управління пам'яттю  
    private const uint MEM_RELEASE = 0x8000;            // Параметр для звільнення зарезервованої пам'яті  
    private const uint PAGE_READONLY = 0x02;            // Пам'ять доступна лише для читання  
    private const uint PAGE_EXECUTE = 0x10;             // Пам'ять може виконуватись (середовище виконання)  
    private const uint PAGE_EXECUTE_READ = 0x20;        // Пам'ять доступна для читання та виконання  
    private const uint PAGE_EXECUTE_READWRITE = 0x40;   // Пам'ять доступна для читання, запису та виконання

    // Зчислення параметрів доступу
    public enum MemoryAccess
    {
        PAGE_READONLY = 0x02,
        PAGE_READWRITE = 0x04,
        PAGE_EXECUTE = 0x10,
        PAGE_EXECUTE_READ = 0x20,
        PAGE_EXECUTE_READWRITE = 0x40
    }

    // P/Invoke для VirtualAlloc
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    // P/Invoke для VirtualProtect
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    // Функція для отримання коду останньої помилки
    [DllImport("kernel32.dll")]
    private static extern uint GetLastError();

    // P/Invoke для VirtualFree
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll")]
    public static extern void GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);


    // Дані для моніторингу  
    private static volatile bool isRunning = true;                                      // Прапорець виконання моніторингового потоку  
    private static ConcurrentQueue<string> memoryLogs = new ConcurrentQueue<string>();  // Черга для зберігання логів пам'яті  


    /// <summary>
    ///                                         ГОЛОВНА ФУНКЦІЯ
    /// </summary>

    static void Main(string[] args)
    {
        Console.WriteLine("Завдання 1 і 2");
        Thread.Sleep(1000);                                 // Затримка на 1 секунду для зручності спостереження результатів 

        // Розмір системної сторінки у байтах
        uint pageSize = (uint)Environment.SystemPageSize;   // Розмір сторінки у байтах
        uint numPages = 10;                                 // Кількість сторінок для резервування
        uint totalSize = pageSize * numPages;               // Загальний розмір у байтах

        // Зарезервувати регіон пам'яті
        IntPtr reservedMemory = VirtualAlloc(IntPtr.Zero, totalSize, MEM_RESERVE, PAGE_NOACCESS);

        // Перевірка на успішність резервування пам'яті
        if (reservedMemory == IntPtr.Zero)
        {
            Console.WriteLine("Помилка резервування пам'яті. Код помилки: " + GetLastError());
            return; // Завершуємо виконання програми у випадку помилки
        }

        Console.WriteLine("Регіон пам'яті зарезервовано");

        // Цикл для обробки кожної сторінки 
        for (uint i = 0; i < numPages; i++)
        {
            // Обчислення адреси кожної сторінки в зарезервованій пам'яті
            IntPtr pageAddress = IntPtr.Add(reservedMemory, (int)(i * pageSize));

            try
            {
                // Комітуємо сторінку перед доступом до неї
                IntPtr committedMemory = VirtualAlloc(pageAddress, pageSize, MEM_COMMIT, PAGE_READWRITE);

                // Перевірка на успішність комітування сторінки
                if (committedMemory == IntPtr.Zero)
                {
                    Console.WriteLine("Помилка комітування сторінки " + i + ". Код помилки: " + GetLastError());
                    continue;   // Продовжуємо наступну ітерацію
                }

                // Перевіряємо доступ до сторінки через VirtualProtect (читаємо і пишемо до сторінки)
                Console.WriteLine("Спроба доступу до сторінки " + i);
                Marshal.WriteByte(pageAddress, 0, 1); // Записуємо байт у сторінку
                Console.WriteLine("Доступ до сторінки " + i);

            }
            catch (Exception ex)
            {
                Console.WriteLine("Помилка доступу до сторінки " + i + ". Код винятку: " + ex.Message);
            }
        }

        Console.WriteLine("Усі сторінки оброблені\n");

        Console.WriteLine("Завдання 3");
        Thread.Sleep(1000);                                 // Затримка на 1 секунду для зручності

        WriteCommandsToFile();                              // Записування команд до файлу

        // Створення та запуск потоків для симуляції операцій з пам'яттю та моніторингу
        Thread simThread = new Thread(() => SimulateMemoryOperations(pageSize, numPages));
        Thread monitorThread = new Thread(MonitorMemory);

        simThread.Start();                                  // Запускаємо потік для симуляції
        monitorThread.Start();                              // Запускаємо потік для моніторингу

        simThread.Join();                                   // Чекаємо на завершення потоку симуляції
        isRunning = false;                                  // Оголошуємо, що симуляція закінчилася, щоб завершити моніторинг
        monitorThread.Join();                               // Чекаємо на завершення потоку моніторингу

        Console.WriteLine("Програма завершена");
        Console.ReadKey();
    }

    /// <summary>
    ///                                         КІНЕЦЬ - ГОЛОВНА ФУНКЦІЯ
    /// </summary>

    // Запис команд до файлу
    private static void WriteCommandsToFile()
    {
        // using - для захисту від "збирача сміття"
        using (StreamWriter writer = new StreamWriter("memory_operations.txt", false))  // false для перезапису файлу  
        {
            writer.WriteLine("0 0 1 4096 PAGE_READWRITE");                          // Резервування регіону  
            writer.WriteLine("100 0 2 2048 PAGE_EXECUTE");                          // Передача блоку  
            writer.WriteLine("200 1 3 512 PAGE_READONLY");                          // Не зберігати блок  
            writer.WriteLine("300 0 4 4096 PAGE_READWRITE");                        // Вивільнення регіону  
            writer.WriteLine("400 1 5 1024 PAGE_EXECUTE_READ");                     // Повернення блоку  
            writer.WriteLine("500 2 6 2048 PAGE_EXECUTE_READWRITE");                // Блокування блоку  
            writer.WriteLine("600 2 7 2048 PAGE_READWRITE");                        // Зняття блокування  
        }
        Console.WriteLine("Команди записані до файлу");
    }

    // Симуляція операцій з пам'яттю
    static void SimulateMemoryOperations(uint pageSize, uint numPages)
    {
        // Читання команд з файлу  
        string[] lines = File.ReadAllLines("memory_operations.txt");

        // Обробка кожного рядка (операції) з файлу 
        foreach (var line in lines)
        {
            // Розділення рядка на частини за пробілами
            var parts = line.Split(' ');

            // Перевірка на валідність рядка  
            if (parts.Length < 5) continue;
            try
            {
                int time = int.Parse(parts[0]);                 // Час затримки перед виконанням  
                int blockNumber = int.Parse(parts[1]);          // Номер блоку пам'яті  
                int operation = int.Parse(parts[2]);            // Тип операції (резервування, коміт і т.д.)  
                uint size = uint.Parse(parts[3]);               // Розмір пам'яті, що обробляється

                // Параметри доступу (серед яких можна вибрати для різних операцій)
                MemoryAccess access;
                // Перетворення п'ятого елементу масиву на значення зчислення MemoryAccess
                if (!Enum.TryParse(parts[4], out access))
                {
                    Console.WriteLine($"Некоректне значення доступу пам'яті: {parts[4]}");
                }             

                // Чекаємо вказаний час перед виконанням 
                Thread.Sleep(time);

                // Калькуляція адреси блоку
                IntPtr blockAddress = IntPtr.Add(IntPtr.Zero, blockNumber * (int)pageSize);

                // Перевірка типу операції і виконання відповідної дій  
                switch (operation)
                {
                    case 1: // Резервування  
                        IntPtr reservedMemory = VirtualAlloc(blockAddress, size, MEM_RESERVE, PAGE_NOACCESS);
                        if (reservedMemory == IntPtr.Zero)
                            memoryLogs.Enqueue($"Помилка резервування пам'яті. Код помилки: {GetLastError()}");
                        else
                            memoryLogs.Enqueue($"Регіон пам'яті зарезервовано: {blockNumber}, Розмір: {size} байт.");
                        break;

                    case 2: // Коміт  
                        IntPtr committedMemory = VirtualAlloc(blockAddress, size, MEM_COMMIT, PAGE_READWRITE);
                        if (committedMemory == IntPtr.Zero)
                            memoryLogs.Enqueue($"Помилка комітування для блоку {blockNumber}. Код помилки: {GetLastError()}");
                        else
                            memoryLogs.Enqueue($"Коміт блоку: {blockNumber}, Розмір: {size} байт.");
                        break;

                    case 3: // Не зберігати в сторінковому файлі  
                        memoryLogs.Enqueue($"Блок {blockNumber} не зберігатиметься в сторінковому файлі.");
                        break;

                    case 4: // Звільнити регіон  
                        if (VirtualFree(blockAddress, 0, MEM_RELEASE))
                            memoryLogs.Enqueue($"Блок {blockNumber} звільнено.");
                        else
                            memoryLogs.Enqueue($"Помилка звільнення блоку {blockNumber}. Код помилки: {GetLastError()}");
                        break;

                    case 5: // Повернути блок  
                        if (VirtualFree(blockAddress, 0, MEM_RELEASE))
                        {
                            memoryLogs.Enqueue($"Блок {blockNumber} повернуто.");
                        }
                        else
                        {
                            memoryLogs.Enqueue($"Помилка повернення блоку {blockNumber}. Код помилки: {GetLastError()}");
                        }
                        break;

                    case 6: // Заблокувати блок  
                        uint oldProtect;
                        if (VirtualProtect(blockAddress, size, PAGE_NOACCESS, out oldProtect))
                            memoryLogs.Enqueue($"Блок {blockNumber} заблоковано.");
                        else
                            memoryLogs.Enqueue($"Помилка блокування блоку {blockNumber}. Код помилки: {GetLastError()}");
                        break;

                    case 7: // Зняти блокування  
                        if (VirtualProtect(blockAddress, size, PAGE_READWRITE, out oldProtect))
                            memoryLogs.Enqueue($"Блок {blockNumber} розблоковано.");
                        else
                            memoryLogs.Enqueue($"Помилка розблокування блоку {blockNumber}. Код помилки: {GetLastError()}");
                        break;

                    default: // Якщо операція не вписується в жоден з кейсів, реєструємо невідому операцію
                        memoryLogs.Enqueue($"Невідома операція: {operation} для блоку {blockNumber}.");
                        break;
                }
            }
            catch (FormatException ex)
            {
                Console.WriteLine("Помилка формату: " + ex.Message);
                // Додати обробку помилки, наприклад, повідомити користувача  
            }
            catch (IndexOutOfRangeException ex)
            {
                Console.WriteLine("Некоректна кількість аргументів: " + ex.Message);
                // Додати обробку помилки щодо недостатньої кількості елементів у 'parts'  
            }
            catch (OverflowException ex)
            {
                Console.WriteLine("Переповнення при конвертації значення: " + ex.Message);
                // Додати обробку помилки в разі, якщо число занадто велике або занадто маленьке  
            }
            catch (Exception ex)
            {
                Console.WriteLine("Сталася непередбачена помилка: " + ex.Message);
                // Обробка будь-яких інших типів помилок  
            }
        }


    }

    // Структура для отримання інформації про пам'ять  
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORYSTATUSEX
    {
        public uint dwLength;                       // Розмір структури, використовуваний для ідентифікації версії 
        public uint dwMemoryLoad;                   // Відсоток пам'яті, що використовується в даний момент (0-100)  
        public ulong ullTotalPhys;                  // Загальний обсяг фізичної пам'яті (в байтах)  
        public ulong ullAvailPhys;                  // Обсяг доступної фізичної пам'яті (в байтах)  
        public ulong ullTotalPageFile;              // Загальний обсяг файлу підкачки (в байтах)  
        public ulong ullAvailPageFile;              // Обсяг доступного файлу підкачки (в байтах)  
        public ulong ullTotalVirtual;               // Загальний обсяг віртуальної пам'яті (в байтах)  
        public ulong ullAvailVirtual;               // Обсяг доступної віртуальної пам'яті (в байтах)  
        public ulong ullExtendedVirtual;            // Обсяг розширеної віртуальної пам'яті (в байтах)
    }

    // Моніторинг пам'яті
    static void MonitorMemory()
    {
        // Цикл, який працює, поки isRunning = true
        while (isRunning)
        {
            // Затримка виконання на 5000 мілісекунд (5 секунд) між моніторингами
            Thread.Sleep(5000); // Інтервал моніторингу  

            // Спробувати вийняти (dequeue) лог з черги пам'яті
            if (memoryLogs.TryDequeue(out string log))
            {
                // Якщо лог вдалося отримати, вивести його на консоль
                Console.WriteLine(log);
            }
            else
            {
                // Якщо черга порожня, повідомити про це 
                Console.WriteLine("Не було нових операцій в пам'яті.");
            }

            // Фіксація стану пам'яті  
            Console.WriteLine("Моніторинг пам'яті");

            // Створити новий екземпляр структури MEMORYSTATUSEX  
            MEMORYSTATUSEX memoryStatus = new MEMORYSTATUSEX();

            // Вказати довжину структури для правильної ідентифікації
            memoryStatus.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));

            // Викликати функцію GlobalMemoryStatusEx для отримання інформації про пам'ять 
            GlobalMemoryStatusEx(ref memoryStatus);

            Console.WriteLine($"Використання пам'яті:\t\t\t{memoryStatus.dwMemoryLoad}%");
            Console.WriteLine($"Всього фізичної пам'яті:\t\t{memoryStatus.ullTotalPhys / 1024 / 1024} МБ");
            Console.WriteLine($"Доступно фізичної пам'яті:\t\t{memoryStatus.ullAvailPhys / 1024 / 1024} МБ");
            Console.WriteLine($"Всього віртуальної пам'яті:\t\t{memoryStatus.ullTotalVirtual / 1024 / 1024} МБ");
            Console.WriteLine($"Доступно віртуальної пам'яті:\t\t{memoryStatus.ullAvailVirtual / 1024 / 1024} МБ");
        }
    }
}