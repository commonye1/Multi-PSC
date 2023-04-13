#include <iostream>
#include <vector>
#include <algorithm>
#include <time.h>
#include <fstream>

using namespace std;

int main() {
    //需要生成Data_kind个数据，每个数据的最大值是Freq_max
    int Data_kind, Freq_max;
    cout << "input the number of data: ";
    cin >> Data_kind;
    cout << "input the max bound of data: ";
    cin >> Freq_max;
    
    vector<int> Data(Data_kind, 0);
    srand(time(0));

    for(int i = 0; i < Data_kind; ++i) {
        Data[i] = rand() % Freq_max + 1;
    }

    fstream Datafile;
    Datafile.open("../data/Data.csv", ios::out);
    if(Datafile && Datafile.is_open()) {
        //cout << "file is opened" << endl;
    }else {
        cout << "failure" << endl;
        return 0;
    }
    int i = 0;
    while(i < Data_kind) {
        Datafile <<" "<<Data[i];
        ++i;
    }
    Datafile.close();



    return 0;
}
