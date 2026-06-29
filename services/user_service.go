package services

type UserService struct{}

func (us *UserService) GetUser() string {
	return "Get User Service"
}
