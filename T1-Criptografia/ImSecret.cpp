#include <opencv2/opencv.hpp>
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Uso: " << argv[0] << " <caminho_da_imagem>\n";
        return 1;
    }

    const std::string imagePath = argv[1];

    cv::Mat image = cv::imread(imagePath, cv::IMREAD_COLOR);

    if (image.empty()) {
        std::cerr << "Erro: nao foi possivel abrir a imagem: "
                  << imagePath << '\n';
        return 1;
    }

    // OpenCV utiliza a ordem BGR:
    // channels[0] = Blue
    // channels[1] = Green
    // channels[2] = Red
    std::vector<cv::Mat> channels;
    cv::split(image, channels);

    cv::Mat blue  = channels[0];
    cv::Mat green = channels[1];
    cv::Mat red   = channels[2];


    cv::Mat new_image;
    std::vector<cv::Mat> new_channels = channels;
    new_channels[0] = green;
    new_channels[1] = red;
    new_channels[2] = blue;
    cv::merge(new_channels, new_image);


    cv::imshow("Imagem original", image);
    cv::imshow("Imagem modificada", new_image);
    std::cout << "Pressione qualquer tecla em uma das janelas para sair.\n";

    cv::waitKey(0);
    cv::destroyAllWindows();

    return 0;
}