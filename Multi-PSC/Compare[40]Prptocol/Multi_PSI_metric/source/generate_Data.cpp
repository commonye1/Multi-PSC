#include <iostream>
#include <vector>
#include <algorithm>
#include <time.h>
#include <fstream>

using namespace std;

int main() {
    //生成gourpNum组数据，每组包含Data_kind个数据，每个数据的最大值是Freq_max
    int groupNum, Data_kind, Freq_max;
    cout << "input the number of data gourp: ";
    cin >> groupNum;
    cout << "input the number of data: ";
    cin >> Data_kind;
    cout << "input the max bound of data: ";
    cin >> Freq_max;
    
    //打开存储数据的文件
    fstream Datafile;
    Datafile.open("../data/S_Freq.csv", ios::out);
    if(Datafile && Datafile.is_open()) {
        //cout << "file is opened" << endl;
    }else {
        cout << "failure" << endl;
        return 0;
    }
    

    vector<int> Data(Data_kind, 0);
    srand(time(0));

    for(int j = 0; j < groupNum; ++j) {
        for(int i = 0; i < Data_kind; ++i) {
            Data[i] = rand() % Freq_max + 1;
            Datafile << " " << Data[i];
        }
        Datafile << endl;
    }

    Datafile.close();

    Datafile.open("../data/T_Freq.csv", ios::out);
    if(Datafile && Datafile.is_open()) {
        //cout << "file is opened" << endl;
    }else {
        cout << "failure" << endl;
        return 0;
    }
    for(int j = 0; j < groupNum; ++j) {
        for(int i = 0; i < Data_kind; ++i) {
            Data[i] = rand() % Freq_max + 1;
            Datafile << " " << Data[i];
        }
        Datafile << endl;
    }

    Datafile.close();


    return 0;
}
