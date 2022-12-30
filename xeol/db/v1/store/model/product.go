package model

import v1 "github.com/noqcks/xeol/xeol/db/v1"

const (
	ProductTableName = "products"
)

type ProductModel struct {
	ID   int    `gorm:"primary_key;column:id;"`
	Name string `gorm:"column:name"`
}

func NewProductModel(product v1.Product) ProductModel {
	return ProductModel{
		ID:   product.ID,
		Name: product.Name,
	}
}

func (m ProductModel) TableName() string {
	return ProductTableName
}

func (m ProductModel) Inflate() (v1.Product, error) {
	return v1.Product{
		ID:   m.ID,
		Name: m.Name,
	}, nil
}
