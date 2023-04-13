#include <iostream>
#include <fstream>
#include <vector>
#include <string>

using namespace std;

int main() {
    ifstream file("../data/data.csv");
    vector<vector<int>> data;

    string line;
    while (getline(file, line)) {
        vector<int> row;   //提取出每一行的数据
        size_t pos = 0;
        string token;
        //string::npos字符串中的最终位置
        //int stoi( const std::string& str, std::size_t* pos = nullptr, int base = 10 );
        while ((pos = line.find(",")) != string::npos) {
            token = line.substr(0, pos);
            row.push_back(stoi(token, 0, 10));  //存储每一行中在逗号之前的位置
            line.erase(0, pos + 1);  //删除已存储的数据
        }
        row.push_back(stoi(line));  //把最后的数据存在row中
        data.push_back(row);   //把这一行的数据存在data中
    }

    // Print out the data
    for (const auto& row : data) {
        for (const auto& col : row) {
            cout << col << " ";
        }
        cout << endl;
    }

    return 0;
}

